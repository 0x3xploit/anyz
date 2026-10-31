//! Address expressions, shared by every flag that takes an address.
//!
//! ```text
//! expr   := [space ':'] term (('+' | '-') term)*
//! space  := 'va' | 'off' | 'offset' | 'rva'
//! term   := number | name | '"' quoted name '"'
//! number := 0x1000 | 4096 | 0o10000 | 0b1000000000000      ('_' separators allowed)
//! name   := symbol | sym.<symbol> | section | entry | base
//!         | sym.imp.<import> | <import>@plt | <import>@stub     call stub (or IAT slot)
//!         | <import>@got | <library>!<import> | <library>!#<n>  pointer slot
//! ```
//!
//! Without a prefix an expression is a virtual address. Names always denote
//! virtual addresses and are converted into the expression's space, so
//! `off:main+4` is the file offset of `main` plus 4.

use serde::Serialize;
use thiserror::Error;

use crate::model::{AddrError, Binary, Format, SymKind, Symbol};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Space {
    Va,
    Offset,
    Rva,
}

impl Space {
    pub fn name(self) -> &'static str {
        match self {
            Space::Va => "VA",
            Space::Offset => "file offset",
            Space::Rva => "RVA",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Term {
    Num(u64),
    Name(String),
}

/// A parsed (not yet resolved) expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expr {
    pub space: Option<Space>,
    terms: Vec<(bool, Term)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExprError {
    #[error("empty address expression")]
    Empty,
    #[error("invalid address expression '{expr}': {msg}")]
    Syntax { expr: String, msg: String },
    #[error("unknown symbol '{name}'{}", did_you_mean(.suggestions))]
    UnknownName {
        name: String,
        suggestions: Vec<String>,
    },
    #[error("import '{0}' has no PLT/stub or pointer-slot address")]
    ImportWithoutAddress(String),
    #[error("'{0}': the binary has no entry point")]
    NoEntry(String),
    #[error("address arithmetic in '{0}' overflows")]
    Overflow(String),
    #[error("'{expr}': {err}{hint}")]
    Translate {
        expr: String,
        err: AddrError,
        hint: String,
    },
}

fn did_you_mean(s: &[String]) -> String {
    match s.len() {
        0 => String::new(),
        _ => format!(" (did you mean {}?)", s.join(", ")),
    }
}

/// The symbol an expression named, when it is exactly one name.
#[derive(Debug, Clone, Serialize)]
pub struct NamedSymbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub kind: SymKind,
    pub thumb: bool,
}

/// A resolved expression, translated into every address space it maps to.
#[derive(Debug, Clone, Serialize)]
pub struct Location {
    pub expr: String,
    /// Space the expression was written in.
    pub space: Space,
    /// Value in that space.
    pub value: u64,
    pub va: Option<u64>,
    pub rva: Option<u64>,
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<NamedSymbol>,
}

impl Location {
    /// The virtual address, or an explanation of why there is none.
    pub fn require_va(&self, bin: &Binary) -> Result<u64, ExprError> {
        if let Some(va) = self.va {
            return Ok(va);
        }
        let err = match self.space {
            Space::Offset => bin
                .offset_to_va(self.value)
                .err()
                .unwrap_or(AddrError::OffsetNotMapped(self.value)),
            _ => AddrError::Unmapped(self.value),
        };
        Err(self.translate_error(bin, err))
    }

    /// A virtual address inside a section or segment (for reading code there).
    pub fn require_mapped_va(&self, bin: &Binary) -> Result<u64, ExprError> {
        let va = self.require_va(bin)?;
        if bin.region_for_va(va).is_none() {
            return Err(self.translate_error(bin, AddrError::Unmapped(va)));
        }
        Ok(va)
    }

    /// The file offset, or an explanation of why there is none.
    pub fn require_offset(&self, bin: &Binary) -> Result<u64, ExprError> {
        if let Some(off) = self.offset {
            return Ok(off);
        }
        let err = match self.va {
            Some(va) => bin
                .va_to_offset(va)
                .err()
                .unwrap_or(AddrError::Unmapped(va)),
            None => AddrError::OffsetPastEnd {
                off: self.value,
                size: bin.bytes().len() as u64,
            },
        };
        Err(self.translate_error(bin, err))
    }

    fn translate_error(&self, bin: &Binary, err: AddrError) -> ExprError {
        ExprError::Translate {
            expr: self.expr.clone(),
            hint: hint(bin, &self.expr, self.space, self.value, &err),
            err,
        }
    }
}

/// Suggest the address space the user probably meant.
fn hint(bin: &Binary, expr: &str, space: Space, value: u64, err: &AddrError) -> String {
    if space != Space::Va || !matches!(err, AddrError::Unmapped(_)) {
        return String::new();
    }
    let mut alts = Vec::new();
    // Only a bare number may have been meant as an RVA or a file offset.
    let body = expr.trim();
    let bare_number = parse_number(body.strip_prefix("va:").unwrap_or(body)).is_some();
    if bare_number
        && bin.image_base != 0
        && value < bin.image_base
        && bin
            .rva_to_va(value)
            .is_ok_and(|va| bin.region_for_va(va).is_some())
    {
        alts.push(format!("rva:{value:#x}"));
    }
    if bare_number && value < bin.bytes().len() as u64 && bin.offset_to_va(value).is_ok() {
        alts.push(format!("off:{value:#x}"));
    }
    match alts.len() {
        0 => match mapped_range(bin) {
            Some((lo, hi)) => format!(" (mapped addresses span {lo:#x}..{hi:#x})"),
            None => String::new(),
        },
        _ => format!(" (did you mean {}?)", alts.join(" or ")),
    }
}

fn mapped_range(bin: &Binary) -> Option<(u64, u64)> {
    let lo = bin.regions.iter().map(|r| r.va).min()?;
    let hi = bin
        .regions
        .iter()
        .map(|r| r.va.saturating_add(r.vsize))
        .max()?;
    Some((lo, hi))
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// `0x401000`, `4198400`, `0o777`, `0b101`, with optional `_` separators.
pub fn parse_number(s: &str) -> Option<u64> {
    let t = s.trim().replace('_', "");
    let lower = t.to_ascii_lowercase();
    let (digits, radix) = if let Some(h) = lower.strip_prefix("0x") {
        (h, 16)
    } else if let Some(b) = lower.strip_prefix("0b") {
        (b, 2)
    } else if let Some(o) = lower.strip_prefix("0o") {
        (o, 8)
    } else {
        (lower.as_str(), 10)
    };
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

fn split_space(s: &str) -> (Option<Space>, &str) {
    if let Some((head, rest)) = s.split_once(':') {
        // `::` belongs to a C++/Rust path, not to a space prefix.
        if !rest.starts_with(':') {
            let space = match head.trim().to_ascii_lowercase().as_str() {
                "va" => Some(Space::Va),
                "off" | "offset" | "file" => Some(Space::Offset),
                "rva" => Some(Space::Rva),
                _ => None,
            };
            if let Some(space) = space {
                return (Some(space), rest);
            }
        }
    }
    (None, s)
}

pub fn parse(input: &str) -> Result<Expr, ExprError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ExprError::Empty);
    }
    let (space, body) = split_space(s);
    let err = |msg: &str| ExprError::Syntax {
        expr: input.trim().to_string(),
        msg: msg.to_string(),
    };
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    let mut terms = Vec::new();
    let mut negative = false;
    let mut expect_term = true;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if expect_term {
            if (c == '+' || c == '-') && terms.is_empty() && !negative {
                negative = c == '-';
                i += 1;
                continue;
            }
            let term = if c == '"' || c == '`' {
                let close = chars[i + 1..]
                    .iter()
                    .position(|&q| q == c)
                    .ok_or_else(|| err("unterminated quoted name"))?;
                let name: String = chars[i + 1..i + 1 + close].iter().collect();
                i += close + 2;
                if name.is_empty() {
                    return Err(err("empty quoted name"));
                }
                Term::Name(name)
            } else {
                let start = i;
                while i < chars.len() && !matches!(chars[i], '+' | '-') && !chars[i].is_whitespace()
                {
                    i += 1;
                }
                let tok: String = chars[start..i].iter().collect();
                if tok.is_empty() {
                    return Err(err("missing operand"));
                }
                if tok.starts_with(|c: char| c.is_ascii_digit()) {
                    Term::Num(
                        parse_number(&tok)
                            .ok_or_else(|| err(&format!("'{tok}' is not a number")))?,
                    )
                } else {
                    Term::Name(tok)
                }
            };
            terms.push((negative, term));
            expect_term = false;
        } else {
            match c {
                '+' => negative = false,
                '-' => negative = true,
                _ => return Err(err(&format!("expected '+' or '-' before '{c}'"))),
            }
            i += 1;
            expect_term = true;
        }
    }
    if terms.is_empty() {
        return Err(ExprError::Empty);
    }
    if expect_term {
        return Err(err("expression ends with an operator"));
    }
    Ok(Expr { space, terms })
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Parse and resolve `input` against `bin`.
pub fn resolve(bin: &Binary, input: &str) -> Result<Location, ExprError> {
    let expr = parse(input)?;
    let space = expr.space.unwrap_or(Space::Va);
    let text = input.trim().to_string();
    let mut acc: i128 = 0;
    let mut named = None;
    for (negative, term) in &expr.terms {
        let v = match term {
            Term::Num(n) => *n,
            Term::Name(name) => {
                let (va, sym) = lookup(bin, name)?;
                if expr.terms.len() == 1 {
                    named = sym;
                }
                to_space(bin, va, space).map_err(|err| ExprError::Translate {
                    expr: text.clone(),
                    hint: String::new(),
                    err,
                })?
            }
        };
        acc = if *negative {
            acc - i128::from(v)
        } else {
            acc + i128::from(v)
        };
    }
    let value = u64::try_from(acc).map_err(|_| ExprError::Overflow(text.clone()))?;

    let (va, offset, rva) = match space {
        Space::Va => (
            Some(value),
            bin.va_to_offset(value).ok(),
            bin.va_to_rva(value).ok(),
        ),
        Space::Offset => {
            let size = bin.bytes().len() as u64;
            if value >= size {
                return Err(ExprError::Translate {
                    expr: text,
                    err: AddrError::OffsetPastEnd { off: value, size },
                    hint: String::new(),
                });
            }
            let va = bin.offset_to_va(value).ok();
            (va, Some(value), va.and_then(|va| bin.va_to_rva(va).ok()))
        }
        Space::Rva => {
            let va = bin.rva_to_va(value).map_err(|err| ExprError::Translate {
                expr: text.clone(),
                err,
                hint: String::new(),
            })?;
            (Some(va), bin.va_to_offset(va).ok(), Some(value))
        }
    };
    Ok(Location {
        expr: text,
        space,
        value,
        va,
        rva,
        offset,
        symbol: named,
    })
}

fn to_space(bin: &Binary, va: u64, space: Space) -> Result<u64, AddrError> {
    match space {
        Space::Va => Ok(va),
        Space::Rva => bin.va_to_rva(va),
        Space::Offset => bin.va_to_offset(va),
    }
}

fn base_name(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

/// Resolve one name to a VA (plus the symbol, when it is one).
fn lookup(bin: &Binary, raw: &str) -> Result<(u64, Option<NamedSymbol>), ExprError> {
    if let Some(rest) = raw
        .strip_prefix("sym.imp.")
        .or_else(|| raw.strip_prefix("imp."))
    {
        return import_addr(bin, rest).map(|a| (a, None));
    }
    let name = raw.strip_prefix("sym.").unwrap_or(raw);
    if let Some(rest) = name
        .strip_suffix("@plt")
        .or_else(|| name.strip_suffix("@stub"))
    {
        return import_addr(bin, rest).map(|a| (a, None));
    }
    if let Some(rest) = name.strip_suffix("@got") {
        return import_slot(bin, None, rest).map(|a| (a, None));
    }
    if let Some(s) = find_symbol(bin, name) {
        let named = NamedSymbol {
            name: s.display_name().to_string(),
            addr: s.addr,
            size: s.size,
            kind: s.kind,
            thumb: s.thumb,
        };
        return Ok((s.addr, Some(named)));
    }
    if let Ok(a) = import_addr(bin, name) {
        return Ok((a, None));
    }
    // `KERNEL32.dll!Sleep`, `kernel32!Sleep`, `ws2_32!#23`: an IAT slot.
    if let Some((lib, func)) = name
        .split_once('!')
        .filter(|(l, f)| !l.is_empty() && !f.is_empty())
    {
        return import_slot(bin, Some(lib), func).map(|a| (a, None));
    }
    if let Some(s) = bin
        .sections
        .iter()
        .find(|s| s.alloc && (s.name == name || s.full_name() == name))
    {
        return Ok((s.addr, None));
    }
    match name.to_ascii_lowercase().as_str() {
        "entry" | "entry0" | "$entry" => {
            return bin
                .entry
                .map(|e| (e, None))
                .ok_or_else(|| ExprError::NoEntry(raw.to_string()));
        }
        "base" | "$base" | "image_base" => return Ok((bin.image_base, None)),
        _ => {}
    }
    Err(ExprError::UnknownName {
        name: raw.to_string(),
        suggestions: suggestions(bin, name),
    })
}

/// Best defined symbol for `name`: raw, versioned, demangled (with or without
/// parameters) or, for Mach-O, the `_`-prefixed C name. Functions win, then
/// globals, then the lowest address.
pub fn find_symbol<'a>(bin: &'a Binary, name: &str) -> Option<&'a Symbol> {
    let macho = bin.format == Format::Macho;
    let matches = |s: &Symbol| {
        s.name == name
            || base_name(&s.name) == name
            || (macho && s.name.strip_prefix('_') == Some(name))
            || s.demangled.as_deref().is_some_and(|d| {
                d == name || d.split('(').next() == Some(name) || base_name(d) == name
            })
    };
    bin.symbols
        .iter()
        .filter(|s| s.defined && !matches!(s.kind, SymKind::File | SymKind::Section) && matches(s))
        .min_by_key(|s| {
            (
                s.kind != SymKind::Func,
                s.bind == crate::model::SymBind::Local,
                s.addr,
            )
        })
}

fn import_addr(bin: &Binary, name: &str) -> Result<u64, ExprError> {
    let macho = bin.format == Format::Macho;
    let imp = bin.imports.iter().find(|i| {
        i.name.as_deref().is_some_and(|n| {
            n == name || base_name(n) == name || (macho && n.strip_prefix('_') == Some(name))
        })
    });
    match imp {
        Some(i) => i
            .plt
            .or(i.slot)
            .ok_or_else(|| ExprError::ImportWithoutAddress(name.to_string())),
        None => Err(ExprError::UnknownName {
            name: name.to_string(),
            suggestions: Vec::new(),
        }),
    }
}

/// The pointer slot (GOT or IAT entry) of an import, optionally from a given
/// library, named with or without its extension (`kernel32` = `KERNEL32.dll`).
/// `#N` selects an import by ordinal.
fn import_slot(bin: &Binary, lib: Option<&str>, name: &str) -> Result<u64, ExprError> {
    let macho = bin.format == Format::Macho;
    let ordinal = name.strip_prefix('#').and_then(parse_number);
    let from_lib = |have: Option<&str>| match (lib, have) {
        (None, _) => true,
        (Some(want), Some(have)) => {
            let file = have.rsplit(['/', '\\']).next().unwrap_or(have);
            file.eq_ignore_ascii_case(want)
                || file
                    .split_once('.')
                    .is_some_and(|(stem, _)| stem.eq_ignore_ascii_case(want))
        }
        (Some(_), None) => false,
    };
    let named = |i: &crate::model::Import| match (&i.name, ordinal) {
        (Some(n), _) => {
            n == name || base_name(n) == name || (macho && n.strip_prefix('_') == Some(name))
        }
        (None, Some(o)) => i.ordinal.map(u64::from) == Some(o),
        (None, None) => i.label() == name,
    };
    let full = match lib {
        Some(l) => format!("{l}!{name}"),
        None => format!("{name}@got"),
    };
    match bin
        .imports
        .iter()
        .find(|i| from_lib(i.library.as_deref()) && named(i))
    {
        Some(i) => i.slot.ok_or(ExprError::ImportWithoutAddress(full)),
        None => Err(ExprError::UnknownName {
            suggestions: suggestions(bin, name),
            name: full,
        }),
    }
}

/// Up to three names close to `name` (case-insensitive match, substring, or
/// small edit distance).
fn suggestions(bin: &Binary, name: &str) -> Vec<String> {
    let want = name.to_ascii_lowercase();
    let macho = bin.format == Format::Macho;
    let mut candidates: Vec<String> = bin
        .symbols
        .iter()
        .filter(|s| s.defined && !matches!(s.kind, SymKind::File | SymKind::Section))
        .map(|s| {
            let n = s.display_name();
            if macho {
                n.strip_prefix('_').unwrap_or(n)
            } else {
                n
            }
            .to_string()
        })
        .chain(bin.imports.iter().filter_map(|i| i.name.clone()))
        .chain(
            bin.sections
                .iter()
                .filter(|s| s.alloc)
                .map(|s| s.name.clone()),
        )
        .collect();
    candidates.sort();
    candidates.dedup();
    let mut scored: Vec<(usize, &String)> = candidates
        .iter()
        .filter_map(|c| {
            let lc = c.to_ascii_lowercase();
            let score = if lc == want {
                0
            } else if lc.contains(&want) && want.len() >= 3 {
                1 + lc.len().saturating_sub(want.len()).min(40)
            } else {
                let d = edit_distance(&lc, &want, 3)?;
                10 + d
            };
            Some((score, c))
        })
        .collect();
    scored.sort();
    scored.into_iter().take(3).map(|(_, c)| c.clone()).collect()
}

/// Levenshtein distance, or `None` once it exceeds `max`.
fn edit_distance(a: &str, b: &str, max: usize) -> Option<usize> {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if a.len().abs_diff(b.len()) > max {
        return None;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            cur[j + 1] = (prev[j] + usize::from(ca != cb))
                .min(prev[j + 1] + 1)
                .min(cur[j] + 1);
        }
        if cur.iter().min().copied().unwrap_or(0) > max {
            return None;
        }
        prev = cur;
    }
    let d = prev[b.len()];
    (d <= max).then_some(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Import, SymBind};

    fn sym(name: &str, addr: u64, size: u64) -> Symbol {
        Symbol {
            name: name.into(),
            demangled: crate::loader::demangle(name),
            addr,
            size,
            kind: SymKind::Func,
            bind: SymBind::Global,
            section: Some(".text".into()),
            defined: true,
            dynamic: false,
            version: None,
            library: None,
            thumb: false,
        }
    }

    fn bin() -> Binary {
        let mut b = crate::model::tests::sample();
        b.symbols = vec![
            sym("main", 0x401100, 0x40),
            sym("win", 0x401136, 0x10),
            sym("_ZN3ctf5checkEPKci", 0x401200, 0x20),
        ];
        let puts = Import {
            name: Some("puts".into()),
            demangled: None,
            ordinal: None,
            library: Some("libc.so.6".into()),
            version: None,
            slot: Some(0x402010),
            plt: Some(0x401030),
            weak: false,
            delayed: false,
        };
        let by_ordinal = Import {
            name: None,
            ordinal: Some(23),
            library: Some("WS2_32.dll".into()),
            slot: Some(0x402020),
            plt: None,
            ..puts.clone()
        };
        b.imports = vec![puts, by_ordinal];
        b
    }

    #[test]
    fn parses_numbers_and_spaces() {
        assert_eq!(parse_number("0x401000"), Some(0x401000));
        assert_eq!(parse_number("4198400"), Some(4198400));
        assert_eq!(parse_number("0X10"), Some(16));
        assert_eq!(parse_number("0b101"), Some(5));
        assert_eq!(parse_number("0x40_0000"), Some(0x400000));
        assert_eq!(parse_number("0x"), None);
        assert_eq!(parse("off:0x1000").unwrap().space, Some(Space::Offset));
        assert_eq!(parse("RVA: 0x10").unwrap().space, Some(Space::Rva));
        assert_eq!(parse("va:main").unwrap().space, Some(Space::Va));
        assert_eq!(
            parse("ctf::check").unwrap().space,
            None,
            ":: is not a prefix"
        );
    }

    #[test]
    fn rejects_bad_syntax() {
        assert_eq!(parse("  "), Err(ExprError::Empty));
        assert!(matches!(parse("main+"), Err(ExprError::Syntax { .. })));
        assert!(matches!(parse("4x"), Err(ExprError::Syntax { .. })));
        assert!(matches!(parse("main 4"), Err(ExprError::Syntax { .. })));
        assert!(matches!(parse("\"open"), Err(ExprError::Syntax { .. })));
    }

    #[test]
    fn resolves_numbers_in_every_space() {
        let b = bin();
        let l = resolve(&b, "0x401234").unwrap();
        assert_eq!(
            (l.va, l.offset, l.rva),
            (Some(0x401234), Some(0x1234), Some(0x1234))
        );
        let l = resolve(&b, "4198400").unwrap();
        assert_eq!(l.va, Some(0x401000));
        let l = resolve(&b, "off:0x1010").unwrap();
        assert_eq!((l.va, l.offset), (Some(0x401010), Some(0x1010)));
        let l = resolve(&b, "rva:0x1010").unwrap();
        assert_eq!(
            (l.va, l.offset, l.rva),
            (Some(0x401010), Some(0x1010), Some(0x1010))
        );
    }

    #[test]
    fn resolves_symbols_with_arithmetic() {
        let b = bin();
        assert_eq!(resolve(&b, "main").unwrap().va, Some(0x401100));
        assert_eq!(resolve(&b, "main+0x20").unwrap().va, Some(0x401120));
        assert_eq!(resolve(&b, "sym.win-4").unwrap().va, Some(0x401132));
        assert_eq!(resolve(&b, "main + 0x10 - 4").unwrap().va, Some(0x40110c));
        assert_eq!(resolve(&b, "off:main+4").unwrap().value, 0x1104);
        assert_eq!(resolve(&b, "rva:win").unwrap().value, 0x1136);
        assert_eq!(resolve(&b, "ctf::check").unwrap().va, Some(0x401200));
        assert_eq!(
            resolve(&b, "\"ctf::check(char const*, int)\"+1")
                .unwrap()
                .va,
            Some(0x401201)
        );
        let l = resolve(&b, "main").unwrap();
        assert_eq!(l.symbol.as_ref().map(|s| s.size), Some(0x40));
        assert!(resolve(&b, "main+1").unwrap().symbol.is_none());
    }

    #[test]
    fn resolves_imports_sections_and_specials() {
        let b = bin();
        assert_eq!(resolve(&b, "puts@plt").unwrap().va, Some(0x401030));
        assert_eq!(resolve(&b, "sym.imp.puts").unwrap().va, Some(0x401030));
        assert_eq!(resolve(&b, "puts").unwrap().va, Some(0x401030));
        assert_eq!(resolve(&b, "puts@got").unwrap().va, Some(0x402010));
        assert_eq!(resolve(&b, "libc.so.6!puts").unwrap().va, Some(0x402010));
        assert_eq!(resolve(&b, "LIBC!puts+8").unwrap().va, Some(0x402018));
        assert!(matches!(
            resolve(&b, "libm.so.6!puts"),
            Err(ExprError::UnknownName { .. })
        ));
        assert!(matches!(
            resolve(&b, "putz@got"),
            Err(ExprError::UnknownName { .. })
        ));
        assert_eq!(resolve(&b, "ws2_32!#23").unwrap().va, Some(0x402020));
        assert_eq!(
            resolve(&b, "\"WS2_32.dll!ordinal 23\"").unwrap().va,
            Some(0x402020)
        );
        assert!(resolve(&b, "ws2_32!#24").is_err());
        assert_eq!(resolve(&b, ".data+8").unwrap().va, Some(0x402008));
        assert_eq!(resolve(&b, "entry").unwrap().va, Some(0x401000));
        assert_eq!(resolve(&b, "base").unwrap().va, Some(0x400000));
    }

    #[test]
    fn unknown_names_get_suggestions() {
        let b = bin();
        match resolve(&b, "mian") {
            Err(ExprError::UnknownName { suggestions, .. }) => assert_eq!(suggestions[0], "main"),
            other => panic!("{other:?}"),
        }
        let msg = resolve(&b, "wni").unwrap_err().to_string();
        assert!(msg.contains("did you mean") && msg.contains("win"), "{msg}");
    }

    #[test]
    fn translation_errors_are_explained() {
        let b = bin();
        // Unmapped VA that is a valid file offset: suggest off:
        let l = resolve(&b, "0x1010").unwrap();
        assert_eq!(l.va, Some(0x1010));
        let err = l.require_offset(&b).unwrap_err().to_string();
        assert!(
            err.contains("off:0x1010") && err.contains("rva:0x1010"),
            "{err}"
        );
        // .bss has no file backing
        let err = resolve(&b, "0x402100")
            .unwrap()
            .require_offset(&b)
            .unwrap_err()
            .to_string();
        assert!(err.contains(".bss"), "{err}");
        // offsets past the end
        assert!(resolve(&b, "off:0x99999").is_err());
        assert!(matches!(resolve(&b, "0-1"), Err(ExprError::Overflow(_))));
    }

    #[test]
    fn edit_distance_bounds() {
        assert_eq!(edit_distance("main", "mian", 3), Some(2));
        assert_eq!(edit_distance("main", "main", 3), Some(0));
        assert_eq!(edit_distance("abc", "xyzxyz", 2), None);
    }
}
