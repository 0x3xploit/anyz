//! Analyzers: pure functions from the unified [`crate::model::Binary`] to plain,
//! serde-serializable report structs. No printing, no colors, no goblin.

pub mod auto;
pub mod checksec;
pub mod disasm;
pub mod entropy;
pub mod find;
pub mod gadgets;
pub mod hexdump;
pub mod info;
pub mod offsets;
mod ordinals;
pub mod sections;
pub mod strings;
pub mod symbols;
pub mod xrefs;

use std::collections::HashMap;

use crate::model::{Binary, Details, Endian, Format, SymKind};

/// Read an unsigned integer of `size` (1, 2, 4 or 8) bytes.
pub(crate) fn read_uint(bytes: &[u8], off: usize, size: usize, endian: Endian) -> Option<u64> {
    let raw = bytes.get(off..off.checked_add(size)?)?;
    let mut v: u64 = 0;
    match endian {
        Endian::Little => {
            for (i, b) in raw.iter().enumerate() {
                v |= u64::from(*b) << (8 * i);
            }
        }
        Endian::Big => {
            for b in raw {
                v = (v << 8) | u64::from(*b);
            }
        }
    }
    Some(v)
}

/// Lower-case hex encoding.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Serialize a byte buffer as a hex string (compact JSON).
pub(crate) fn serialize_hex<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex(bytes))
}

/// Strip the Mach-O C symbol prefix so names compare across formats.
pub(crate) fn c_name(name: &str, macho: bool) -> &str {
    if macho {
        name.strip_prefix('_').unwrap_or(name)
    } else {
        name
    }
}

/// Address -> name lookups used to annotate disassembly and references:
/// symbols (`main+0x20`), call stubs (`puts@plt`), pointer slots (`puts@got`,
/// `KERNEL32.dll!Sleep`) and string literals.
pub struct Names<'a> {
    bin: &'a Binary,
    /// Defined symbols sorted by address: (start, size, name).
    ranges: Vec<(u64, u64, &'a str)>,
    stubs: HashMap<u64, String>,
    slots: HashMap<u64, String>,
}

impl<'a> Names<'a> {
    pub fn new(bin: &'a Binary) -> Self {
        let mut ranges: Vec<(u64, u64, &str, bool)> = bin
            .symbols
            .iter()
            .filter(|s| {
                s.defined
                    && !matches!(s.kind, SymKind::File | SymKind::Section)
                    && s.section.as_deref() != Some("ABS")
                    && s.name != "__mh_execute_header"
            })
            .map(|s| (s.addr, s.size, s.display_name(), s.kind == SymKind::Func))
            .collect();
        // Functions first at equal addresses, so dedup keeps them.
        ranges.sort_by(|a, b| a.0.cmp(&b.0).then(b.3.cmp(&a.3)));
        ranges.dedup_by_key(|r| r.0);

        let mut stubs = HashMap::new();
        let mut slots = HashMap::new();
        if let Details::Elf(e) = &bin.details {
            for p in &e.plt {
                stubs.insert(p.addr, format!("{}@plt", p.name));
            }
        }
        for imp in &bin.imports {
            let label = imp.label();
            if let Some(plt) = imp.plt {
                let suffix = if bin.format == Format::Macho {
                    "stub"
                } else {
                    "plt"
                };
                stubs
                    .entry(plt)
                    .or_insert_with(|| format!("{label}@{suffix}"));
            }
            if let Some(slot) = imp.slot {
                let name = match (bin.format, &imp.library) {
                    (Format::Pe, Some(lib)) => format!("{lib}!{label}"),
                    _ => format!("{label}@got"),
                };
                slots.entry(slot).or_insert(name);
            }
        }
        Names {
            bin,
            ranges: ranges.into_iter().map(|(a, s, n, _)| (a, s, n)).collect(),
            stubs,
            slots,
        }
    }

    /// Symbol or stub starting exactly at `va`.
    pub fn exact(&self, va: u64) -> Option<String> {
        if let Some(s) = self.stubs.get(&va) {
            return Some(s.clone());
        }
        let i = self.ranges.partition_point(|r| r.0 < va);
        self.ranges
            .get(i)
            .filter(|r| r.0 == va)
            .map(|r| r.2.to_string())
    }

    /// `win`, `main+0x20`, `puts@plt`, `puts@got`, or `None`.
    pub fn describe(&self, va: u64) -> Option<String> {
        if let Some(s) = self.stubs.get(&va).or_else(|| self.slots.get(&va)) {
            return Some(s.clone());
        }
        let i = self.ranges.partition_point(|r| r.0 <= va);
        let (start, size, name) = *self.ranges.get(i.checked_sub(1)?)?;
        let delta = va - start;
        let next = self.ranges.get(i).map_or(u64::MAX, |r| r.0);
        let inside = if size > 0 {
            delta < size
        } else {
            delta < 0x200 && va < next
        };
        if !inside {
            return None;
        }
        Some(if delta == 0 {
            name.to_string()
        } else {
            format!("{name}+{delta:#x}")
        })
    }

    /// Like [`Names::describe`], falling back to `section+off` (`.plt`, `.text+0x40`)
    /// for code addresses without a symbol (e.g. in stripped binaries).
    pub fn describe_code(&self, va: u64) -> Option<String> {
        self.describe(va).or_else(|| {
            let s = self.bin.section_for_va(va)?;
            let delta = va - s.addr;
            let name = s.full_name();
            Some(if delta == 0 {
                name
            } else {
                format!("{name}+{delta:#x}")
            })
        })
    }

    /// Name of a pointer slot (GOT / IAT entry).
    pub fn slot(&self, va: u64) -> Option<&str> {
        self.slots.get(&va).map(String::as_str)
    }

    /// Printable C (or UTF-16LE) string at `va`, escaped and shortened.
    pub fn string_at(&self, va: u64) -> Option<String> {
        const MAX: usize = 60;
        let raw = self.bin.bytes_at_va(va, 256).ok()?;
        let printable = |b: u8| (0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r');
        let ascii_len = raw.iter().position(|&b| b == 0)?;
        let (text, wide): (String, bool) =
            if ascii_len >= 2 && raw[..ascii_len].iter().all(|&b| printable(b)) {
                (
                    raw[..ascii_len].iter().map(|&b| char::from(b)).collect(),
                    false,
                )
            } else {
                let units: Vec<u16> = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&c| u16::from_le_bytes(c))
                    .take_while(|&u| u != 0)
                    .collect();
                if units.len() < 2
                    || units.len() * 2 >= raw.len()
                    || !units.iter().all(|&u| u < 0x80 && printable(u as u8))
                {
                    return None;
                }
                (units.iter().map(|&u| char::from(u as u8)).collect(), true)
            };
        let mut esc = String::with_capacity(text.len());
        for c in text.chars() {
            match c {
                '\n' => esc.push_str("\\n"),
                '\r' => esc.push_str("\\r"),
                '\t' => esc.push_str("\\t"),
                '"' => esc.push_str("\\\""),
                '\\' => esc.push_str("\\\\"),
                c => esc.push(c),
            }
        }
        if esc.chars().count() > MAX {
            esc = esc.chars().take(MAX).collect::<String>() + "...";
        }
        Some(if wide {
            format!("L\"{esc}\"")
        } else {
            format!("\"{esc}\"")
        })
    }
}
