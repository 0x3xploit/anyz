//! Report -> [`Doc`]: what each view shows, in which order, with which tones.
//! Shared by the pretty and plain backends, so every view is laid out once.

use std::time::{SystemTime, UNIX_EPOCH};

use super::{Align, Block, Column, Doc, Group, Line, Panel, Report, Span, Table, Tone};
use crate::addr::Space;
use crate::analyzers::checksec::Mitigation;
use crate::analyzers::disasm::{DisasmReport, RefKind};
use crate::analyzers::hexdump::HexdumpReport;
use crate::analyzers::info::{InfoReport, Linking};
use crate::analyzers::offsets::OffsetsReport;
use crate::analyzers::sections::{SectionsReport, SegmentsReport};
use crate::analyzers::symbols::{SymbolRow, SymbolsReport};
use crate::model::{Details, Format, SymBind, SymKind};

pub fn doc(r: &Report) -> Doc {
    match r {
        Report::Info(i) => info(i),
        Report::Sections(s) => sections(s),
        Report::Segments(s) => segments(s),
        Report::Symbols(s) => symbols(s),
        Report::Disasm(d) => disasm(d),
        Report::Offsets(o) => offsets(o),
        Report::Hexdump(h) => hexdump(h),
        Report::Checksec(c) => checksec(c),
        Report::Imports(i) => imports(i),
        Report::Exports(e) => exports(e),
        Report::Plt(p) => plt(p),
        Report::Got(g) => got(g),
        Report::Relocs(r) => relocs(r),
        Report::Entropy(e) => entropy(e),
        Report::Strings(s) => strings(s),
        Report::Auto(a) => auto(a),
        Report::Find(f) => find(f),
        Report::Xrefs(x) => xrefs(x),
        Report::Gadgets(g) => gadgets(g),
    }
}

// ---------------------------------------------------------------------------
// Milestone 4 views: findings, find, xrefs, gadgets
// ---------------------------------------------------------------------------

fn auto(r: &crate::analyzers::auto::AutoReport) -> Doc {
    use crate::analyzers::auto::{Category, Severity};
    use Tone::*;
    let sub = format!("{} high, {} warn, {} info", r.high, r.warn, r.info);
    let mut blocks = vec![heading("Findings", Some(sub))];
    if r.findings.is_empty() {
        blocks.push(Block::Note(vec![s("nothing notable found", Good)]));
        return Doc { blocks };
    }
    let mut lines = Vec::new();
    for f in &r.findings {
        let (label, tone) = match f.severity {
            Severity::High => ("HIGH", Bad),
            Severity::Warn => ("WARN", Warn),
            Severity::Info => ("INFO", Dim),
        };
        let cat = match f.category {
            Category::Ctf => "ctf",
            Category::Malware => "malware",
            Category::General => "general",
        };
        lines.push(vec![
            s(format!(" {label} "), tone),
            s(format!(" {cat:<8}"), Dim),
            s(
                &f.title,
                if f.severity == Severity::Info {
                    Normal
                } else {
                    Bold
                },
            ),
        ]);
        for e in &f.evidence {
            lines.push(vec![s(format!("{:16}- ", ""), Dim), s(e, Normal)]);
        }
    }
    blocks.push(Block::Lines(lines));
    Doc { blocks }
}

fn find(r: &crate::analyzers::find::FindReport) -> Doc {
    use Align::*;
    use Tone::*;
    let kind = match r.kind {
        crate::analyzers::find::PatternKind::Hex => "bytes",
        crate::analyzers::find::PatternKind::String => "string",
        crate::analyzers::find::PatternKind::Utf16 => "utf-16 string",
    };
    let sub = format!(
        "'{}' as {kind} ({} bytes): {} matches",
        r.pattern, r.length, r.total
    );
    let mut blocks = vec![heading("Find", Some(sub))];
    if r.truncated {
        blocks.push(Block::Note(vec![s(
            format!("showing the first {} matches", r.matches.len()),
            Warn,
        )]));
    }
    if r.matches.is_empty() {
        blocks.push(Block::Note(vec![s("no matches", Dim)]));
        return Doc { blocks };
    }
    let ow = hex_width(r.matches.iter().map(|m| m.offset));
    let vw = hex_width(r.matches.iter().filter_map(|m| m.va));
    let rows = r
        .matches
        .iter()
        .map(|m| {
            let bytes: Vec<String> = m.context.iter().map(|b| format!("{b:02x}")).collect();
            vec![
                s(hex_w(m.offset, ow), Offset),
                opt_hex(m.va, vw, Addr),
                s(m.section.as_deref().unwrap_or("-"), Section),
                s(
                    m.symbol
                        .as_deref()
                        .map(|x| short(x, 40))
                        .unwrap_or_default(),
                    Func,
                ),
                s(bytes.join(" "), Dim),
            ]
        })
        .collect();
    blocks.push(Block::Table(Table {
        columns: columns(&[
            ("Offset", Left),
            ("VA", Left),
            ("Section", Left),
            ("Symbol", Left),
            ("Bytes", Left),
        ]),
        rows,
    }));
    Doc { blocks }
}

fn xrefs(r: &crate::analyzers::xrefs::XrefsReport) -> Doc {
    use Align::*;
    use Tone::*;
    let target = match &r.name {
        Some(n) => format!("{} ({:#x})", short(n, 60), r.target),
        None => format!("{:#x}", r.target),
    };
    let sub = format!(
        "{target}: {} references, scanned {}",
        r.total,
        r.scanned.join(" ")
    );
    let mut blocks = vec![heading("Xrefs", Some(sub))];
    for n in &r.notes {
        blocks.push(Block::Note(vec![s(n, Dim)]));
    }
    if r.refs.is_empty() {
        blocks.push(Block::Note(vec![s("no references found", Dim)]));
        return Doc { blocks };
    }
    let aw = hex_width(r.refs.iter().map(|x| x.addr));
    let rows = r
        .refs
        .iter()
        .map(|x| {
            let kind = match x.kind {
                crate::analyzers::disasm::RefKind::Code => "code",
                crate::analyzers::disasm::RefKind::Data => "data",
                crate::analyzers::disasm::RefKind::Slot => "slot",
            };
            vec![
                s(hex_w(x.addr, aw), Addr),
                s(
                    x.function
                        .as_deref()
                        .map(|f| short(f, 50))
                        .unwrap_or_else(|| "-".into()),
                    Func,
                ),
                s(kind, Dim),
                s(
                    format!("{} {}", x.mnemonic, x.operands)
                        .trim_end()
                        .to_string(),
                    Insn(x.class),
                ),
            ]
        })
        .collect();
    blocks.push(Block::Table(Table {
        columns: columns(&[
            ("Address", Left),
            ("Function", Left),
            ("Kind", Left),
            ("Instruction", Left),
        ]),
        rows,
    }));
    Doc { blocks }
}

fn gadgets(r: &crate::analyzers::gadgets::GadgetsReport) -> Doc {
    use Align::*;
    use Tone::*;
    let mut blocks = vec![heading(
        "Gadgets",
        Some(format!(
            "{} unique, {}, up to {} instructions + return",
            r.total, r.arch, r.depth
        )),
    )];
    if r.truncated {
        blocks.push(Block::Note(vec![s(
            format!("showing the first {} gadgets", r.gadgets.len()),
            Warn,
        )]));
    }
    if r.gadgets.is_empty() {
        blocks.push(Block::Note(vec![s("no gadgets found", Dim)]));
        return Doc { blocks };
    }
    let aw = hex_width(r.gadgets.iter().map(|g| g.addr));
    let rows = r
        .gadgets
        .iter()
        .map(|g| {
            let tone = if g.tags.iter().any(|t| matches!(*t, "syscall" | "pivot")) {
                Bad
            } else if g.tags.contains(&"pop-reg") {
                Good
            } else {
                Normal
            };
            vec![
                s(hex_w(g.addr, aw), Addr),
                s(&g.text, tone),
                s(g.tags.join(" "), Dim),
            ]
        })
        .collect();
    blocks.push(Block::Table(Table {
        columns: columns(&[("Address", Left), ("Gadget", Left), ("Tags", Left)]),
        rows,
    }));
    Doc { blocks }
}

// ---------------------------------------------------------------------------
// Milestone 3 views: checksec, imports/exports, plt/got, relocs, entropy, strings
// ---------------------------------------------------------------------------

fn status_word(st: crate::analyzers::checksec::Status) -> &'static str {
    use crate::analyzers::checksec::Status;
    match st {
        Status::Enabled => "enabled",
        Status::Partial => "partial",
        Status::Disabled => "disabled",
        Status::NotApplicable => "n/a",
    }
}

fn checksec(r: &crate::analyzers::checksec::ChecksecReport) -> Doc {
    use Align::*;
    use Tone::*;
    let mut blocks = vec![heading("Checksec", Some(r.format.name().to_string()))];
    if r.items.is_empty() {
        blocks.push(Block::Note(vec![s(
            "no mitigations apply to raw data",
            Dim,
        )]));
        return Doc { blocks };
    }
    let rows = r
        .items
        .iter()
        .map(|m| {
            vec![
                s(m.name, Bold),
                s(status_word(m.status), Badge(m.status)),
                s(&m.value, Normal),
                s(m.detail.as_deref().unwrap_or(""), Dim),
            ]
        })
        .collect();
    blocks.push(Block::Table(Table {
        columns: columns(&[
            ("Mitigation", Left),
            ("Status", Left),
            ("Value", Left),
            ("Detail", Left),
        ]),
        rows,
    }));
    if !r.extra.is_empty() {
        use crate::analyzers::checksec::{Status, Verdict};
        let rows = r
            .extra
            .iter()
            .map(|p| {
                let badge = match p.verdict {
                    Verdict::Good => Status::Enabled,
                    Verdict::Bad => Status::Disabled,
                    Verdict::Neutral => Status::NotApplicable,
                };
                vec![
                    s(p.name, Bold),
                    s(&p.value, Badge(badge)),
                    s(p.detail.as_deref().unwrap_or(""), Dim),
                ]
            })
            .collect();
        blocks.push(Block::Note(Vec::new()));
        blocks.push(Block::Table(Table {
            columns: columns(&[("Property", Left), ("Value", Left), ("Detail", Left)]),
            rows,
        }));
    }
    Doc { blocks }
}

fn opt_hex(v: Option<u64>, w: usize, tone: Tone) -> Span {
    match v {
        Some(v) => s(hex_w(v, w), tone),
        None => s("-", Tone::Dim),
    }
}

fn imports(r: &crate::analyzers::symbols::ImportsReport) -> Doc {
    use Align::*;
    use Tone::*;
    let libs = r.libraries.iter().filter(|l| l.library.is_some()).count();
    let sub = format!("{} from {libs} libraries, {} risky", r.total, r.risky);
    let mut blocks = vec![heading("Imports", Some(sub))];
    if r.total == 0 {
        blocks.push(Block::Note(vec![s(
            "no imports (static binary or raw data)",
            Dim,
        )]));
        return Doc { blocks };
    }
    let all = r.libraries.iter().flat_map(|l| &l.imports);
    let sw = hex_width(all.clone().filter_map(|i| i.slot));
    let pw = hex_width(all.filter_map(|i| i.plt));
    let has_plt = r
        .libraries
        .iter()
        .flat_map(|l| &l.imports)
        .any(|i| i.plt.is_some());
    let mut rows = Vec::new();
    for lib in &r.libraries {
        for (n, i) in lib.imports.iter().enumerate() {
            let mut notes = Vec::new();
            if let Some(o) = i.ordinal {
                notes.push(format!("ordinal {o}"));
            }
            if let Some(v) = &i.version {
                notes.push(v.clone());
            }
            if i.weak {
                notes.push("weak".into());
            }
            if i.delayed {
                notes.push("delay-load".into());
            }
            let (name_tone, risk) = match i.risk {
                Some(r) if r.high() => (Bad, format!("[{}]", r.label())),
                Some(r) => (Warn, format!("[{}]", r.label())),
                None => (Normal, String::new()),
            };
            let lib_name = lib.library.as_deref().unwrap_or("?");
            let mut row = vec![
                s(lib_name, if n == 0 { Library } else { Dim }),
                s(i.demangled.as_deref().unwrap_or(&i.name), name_tone),
                s(risk, name_tone),
                opt_hex(i.slot, sw, Addr),
            ];
            if has_plt {
                row.push(opt_hex(i.plt, pw, Addr));
            }
            row.push(s(notes.join(", "), Dim));
            rows.push(row);
        }
    }
    let mut cols = vec![
        ("Library", Left),
        ("Function", Left),
        ("Risk", Left),
        ("Slot", Left),
    ];
    if has_plt {
        cols.push(("PLT/stub", Left));
    }
    cols.push(("Notes", Left));
    blocks.push(Block::Table(Table {
        columns: columns(&cols),
        rows,
    }));
    Doc { blocks }
}

fn exports(r: &crate::analyzers::symbols::ExportsReport) -> Doc {
    use Align::*;
    use Tone::*;
    let mut blocks = vec![heading("Exports", Some(r.total.to_string()))];
    if r.exports.is_empty() {
        blocks.push(Block::Note(vec![s("no exports", Dim)]));
        return Doc { blocks };
    }
    let aw = hex_width(r.exports.iter().map(|e| e.addr));
    let has_ord = r.exports.iter().any(|e| e.ordinal.is_some());
    let rows = r
        .exports
        .iter()
        .map(|e| {
            let name = e
                .demangled
                .as_deref()
                .or(e.name.as_deref())
                .unwrap_or("(by ordinal)");
            let mut row = vec![if e.forwarder.is_some() {
                s("-", Dim)
            } else {
                s(hex_w(e.addr, aw), Addr)
            }];
            if has_ord {
                row.push(s(e.ordinal.map(|o| o.to_string()).unwrap_or_default(), Num));
            }
            row.push(s(e.kind.name(), kind_tone(e.kind)));
            row.push(s(
                name,
                if e.name.is_none() {
                    Dim
                } else {
                    kind_tone(e.kind)
                },
            ));
            row.push(s(
                e.forwarder
                    .as_deref()
                    .map(|f| format!("-> {f}"))
                    .unwrap_or_default(),
                Warn,
            ));
            row
        })
        .collect();
    let mut cols = vec![("Address", Left)];
    if has_ord {
        cols.push(("Ordinal", Right));
    }
    cols.extend([("Kind", Left), ("Name", Left), ("Forwarder", Left)]);
    blocks.push(Block::Table(Table {
        columns: columns(&cols),
        rows,
    }));
    Doc { blocks }
}

fn plt(r: &crate::analyzers::symbols::PltReport) -> Doc {
    use Align::*;
    use Tone::*;
    let mut blocks = vec![heading("PLT", Some(r.entries.len().to_string()))];
    if let Some(n) = &r.note {
        blocks.push(Block::Note(vec![s(n, Dim)]));
    }
    if r.entries.is_empty() {
        return Doc { blocks };
    }
    let aw = hex_width(r.entries.iter().map(|e| e.addr));
    let sw = hex_width(r.entries.iter().filter_map(|e| e.slot));
    let rows = r
        .entries
        .iter()
        .map(|e| {
            let name = e.demangled.as_deref().unwrap_or(&e.name);
            let tone = match crate::analyzers::symbols::risk(&e.name) {
                Some(r) if r.high() => Bad,
                Some(_) => Warn,
                None => Func,
            };
            vec![
                s(hex_w(e.addr, aw), Addr),
                s(e.section.as_deref().unwrap_or(""), Section),
                s(name, tone),
                opt_hex(e.slot, sw, Addr),
            ]
        })
        .collect();
    blocks.push(Block::Table(Table {
        columns: columns(&[
            ("Stub", Left),
            ("Section", Left),
            ("Function", Left),
            ("GOT slot", Left),
        ]),
        rows,
    }));
    Doc { blocks }
}

fn got(r: &crate::analyzers::symbols::GotReport) -> Doc {
    use Align::*;
    use Tone::*;
    let title = if r.format == Format::Pe { "IAT" } else { "GOT" };
    let mut blocks = vec![heading(title, Some(r.entries.len().to_string()))];
    if let Some(n) = &r.note {
        blocks.push(Block::Note(vec![s(n, Dim)]));
    }
    if r.entries.is_empty() {
        return Doc { blocks };
    }
    let aw = hex_width(r.entries.iter().map(|e| e.addr));
    let vw = hex_width(r.entries.iter().filter_map(|e| e.value));
    let rows = r
        .entries
        .iter()
        .map(|e| {
            vec![
                s(hex_w(e.addr, aw), Addr),
                opt_hex(e.value, vw, Num),
                s(e.section.as_deref().unwrap_or(""), Section),
                s(&e.kind, Dim),
                s(e.name.as_deref().unwrap_or(""), Func),
            ]
        })
        .collect();
    blocks.push(Block::Table(Table {
        columns: columns(&[
            ("Slot", Left),
            ("Value", Left),
            ("Section", Left),
            ("Type", Left),
            ("Symbol", Left),
        ]),
        rows,
    }));
    Doc { blocks }
}

fn relocs(r: &crate::analyzers::symbols::RelocsReport) -> Doc {
    use Align::*;
    use Tone::*;
    let mut blocks = vec![heading("Relocations", Some(r.total.to_string()))];
    if let Some(n) = &r.note {
        blocks.push(Block::Note(vec![s(n, Dim)]));
    }
    if r.relocations.is_empty() {
        return Doc { blocks };
    }
    let aw = hex_width(r.relocations.iter().map(|e| e.addr));
    let rows = r
        .relocations
        .iter()
        .map(|e| {
            let target = match (&e.symbol, e.addend) {
                (Some(sym), Some(a)) if a != 0 => format!(
                    "{sym} {} {:#x}",
                    if a < 0 { '-' } else { '+' },
                    a.unsigned_abs()
                ),
                (Some(sym), _) => sym.clone(),
                (None, Some(a)) => format!("{a:#x}"),
                (None, None) => String::new(),
            };
            vec![
                s(hex_w(e.addr, aw), Addr),
                s(&e.kind, Normal),
                s(target, Func),
                s(&e.table, Dim),
                s(e.section.as_deref().unwrap_or(""), Section),
            ]
        })
        .collect();
    blocks.push(Block::Table(Table {
        columns: columns(&[
            ("Address", Left),
            ("Type", Left),
            ("Symbol + addend", Left),
            ("Table", Left),
            ("Section", Left),
        ]),
        rows,
    }));
    Doc { blocks }
}

fn entropy(r: &crate::analyzers::entropy::EntropyReport) -> Doc {
    use Align::*;
    use Tone::*;
    let sub = format!(
        "whole file {:.2} bits/byte, {} blocks of {} bytes; above {:.1} suggests compression or encryption",
        r.file_entropy,
        r.blocks.len(),
        r.block_size,
        r.threshold
    );
    let mut blocks = vec![heading("Entropy", Some(sub))];
    let mut spark = vec![s("profile  ", Dim)];
    spark.extend(r.blocks.iter().map(|&e| s("", Spark(e))));
    let max = r.blocks.iter().copied().fold(0.0f64, f64::max);
    spark.push(s(format!("  max {max:.2}"), Dim));
    blocks.push(Block::Lines(vec![spark]));
    let rows = r
        .sections
        .iter()
        .map(|x| {
            vec![
                s(&x.name, Section),
                s(hex(x.offset), Offset),
                s(hex(x.size), Num),
                s(x.perms.to_string(), Perm(x.perms)),
                match x.entropy {
                    Some(e) => s(format!("{e:.2}"), Num),
                    None => s("-", Dim),
                },
                match x.entropy {
                    Some(e) => s("", Bar(e, 32)),
                    None => s("", Dim),
                },
            ]
        })
        .collect();
    if !r.sections.is_empty() {
        blocks.push(Block::Table(Table {
            columns: columns(&[
                ("Section", Left),
                ("Offset", Left),
                ("Size", Right),
                ("Perms", Left),
                ("Entropy", Right),
                ("", Left),
            ]),
            rows,
        }));
    }
    Doc { blocks }
}

fn strings(r: &crate::analyzers::strings::StringsReport) -> Doc {
    use Align::*;
    use Tone::*;
    let enc = if r.utf16 { "ascii + utf-16le" } else { "ascii" };
    let mut blocks = vec![heading(
        "Strings",
        Some(format!(
            "{}, {enc}, min length {}",
            r.strings.len(),
            r.min_len
        )),
    )];
    if r.strings.is_empty() {
        blocks.push(Block::Note(vec![s("no strings found", Dim)]));
        return Doc { blocks };
    }
    let ow = hex_width(r.strings.iter().map(|x| x.offset));
    let vw = hex_width(r.strings.iter().filter_map(|x| x.va));
    let rows = r
        .strings
        .iter()
        .map(|x| {
            let mut row = vec![
                s(hex_w(x.offset, ow), Offset),
                opt_hex(x.va, vw, Addr),
                s(x.section.as_deref().unwrap_or("-"), Section),
            ];
            if r.utf16 {
                row.push(s(
                    match x.encoding {
                        crate::analyzers::strings::Encoding::Ascii => "a",
                        crate::analyzers::strings::Encoding::Utf16 => "u",
                    },
                    Dim,
                ));
            }
            row.push(s(short(&x.value, 400), Str));
            row
        })
        .collect();
    let mut cols = vec![("Offset", Left), ("VA", Left), ("Section", Left)];
    if r.utf16 {
        cols.push(("Enc", Left));
    }
    cols.push(("String", Left));
    blocks.push(Block::Table(Table {
        columns: columns(&cols),
        rows,
    }));
    Doc { blocks }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn s(text: impl Into<String>, tone: Tone) -> Span {
    Span::new(text, tone)
}

fn sep() -> Span {
    Span::new("", Tone::Sep)
}

pub fn hex(v: u64) -> String {
    format!("{v:#x}")
}

fn hex_w(v: u64, w: usize) -> String {
    format!("0x{v:0w$x}")
}

/// Hex digits needed for the widest value (at least 4), for aligned columns.
fn hex_width(values: impl Iterator<Item = u64>) -> usize {
    values
        .map(|v| (64 - v.leading_zeros() as usize).div_ceil(4))
        .max()
        .unwrap_or(0)
        .max(4)
}

pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `YYYY-MM-DD HH:MM:SS UTC` without pulling in a date crate.
pub fn utc_date(ts: u64) -> String {
    let (days, secs) = ((ts / 86_400) as i64, ts % 86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

fn heading(title: &str, subtitle: Option<String>) -> Block {
    Block::Heading {
        title: title.to_string(),
        subtitle,
    }
}

fn columns(spec: &[(&str, Align)]) -> Vec<Column> {
    spec.iter()
        .map(|(name, align)| Column {
            name: name.to_string(),
            align: *align,
        })
        .collect()
}

fn badge_label(m: &Mitigation) -> String {
    match m.value.as_str() {
        "yes" | "no" | "n/a" => m.name.to_string(),
        v => format!("{} ({v})", m.name),
    }
}

// ---------------------------------------------------------------------------
// Info panel
// ---------------------------------------------------------------------------

fn info(r: &InfoReport) -> Doc {
    use Tone::*;
    let mut groups = Vec::new();

    let mut g = Group::new(None);
    g.row("File", vec![s(&r.path, Path)]);
    g.row(
        "Format",
        vec![s(&r.format_label, Bold), sep(), s(&r.kind, Normal)],
    );
    let mut arch = vec![s(r.arch.name(), Bold)];
    if let Some(v) = &r.arch_variant {
        arch.push(s(format!(" ({v})"), Dim));
    }
    if r.bits > 0 {
        arch.extend([
            sep(),
            s(format!("{}-bit", r.bits), Normal),
            sep(),
            s(r.endian.name(), Normal),
        ]);
    }
    g.row("Arch", arch);
    if r.format != Format::Raw {
        let mut os = vec![s(&r.os, Normal)];
        if let Some(abi) = &r.abi {
            os.extend([sep(), s(abi, Dim)]);
        }
        g.row("OS/ABI", os);
    }
    g.row("Entry", entry_line(r));
    g.row("Image base", vec![s(hex(r.image_base), Addr)]);
    g.row(
        "Size",
        vec![
            s(human_size(r.file_size), Num),
            s(format!(" ({} bytes)", thousands(r.file_size)), Dim),
        ],
    );
    groups.push(g);

    let mut g = Group::new(Some("Hashes"));
    g.row("MD5", vec![s(&r.hashes.md5, Hash)]);
    g.row("SHA1", vec![s(&r.hashes.sha1, Hash)]);
    g.row("SHA256", vec![s(&r.hashes.sha256, Hash)]);
    if let Some(ih) = &r.hashes.imphash {
        g.row("Imphash", vec![s(ih, Hash)]);
    }
    groups.push(g);

    let mut g = Group::new(Some("Linking"));
    let link = match r.linking {
        Linking::Dynamic => Some(s("dynamic", Normal)),
        Linking::Static => Some(s("static", Bold)),
        Linking::StaticPie => Some(s("static-pie", Bold)),
        Linking::NotApplicable => None,
    };
    if let Some(l) = link {
        g.row("Linking", vec![l]);
    }
    if let Some(i) = &r.interpreter {
        g.row("Interpreter", vec![s(i, Path)]);
    }
    if !r.libraries.is_empty() {
        g.row("Libraries", libraries_line(r));
    }
    if let Some(stripped) = r.stripped {
        let mut l = vec![if stripped {
            s("yes", Warn)
        } else {
            s("no", Good)
        }];
        if let Details::Pe(p) = &r.details
            && stripped
            && p.pdb.is_some()
        {
            l.extend([sep(), s("symbols in external PDB", Dim)]);
        }
        if r.debug_info {
            l.extend([sep(), s("debug info present", Good)]);
        }
        g.row("Stripped", l);
    }
    format_rows(r, &mut g);
    if !g.rows.is_empty() {
        groups.push(g);
    }

    let mut g = Group::new(Some("Security"));
    if r.mitigations.is_empty() {
        g.row("Mitigations", vec![s("n/a", Dim)]);
    } else {
        let mut l = Vec::new();
        for (i, m) in r.mitigations.iter().enumerate() {
            if i > 0 {
                l.push(s("  ", Normal));
            }
            l.push(s(badge_label(m), Badge(m.status)));
        }
        g.row("Mitigations", l);
    }
    groups.push(g);

    let mut g = Group::new(Some("Analysis"));
    if r.toolchain.is_empty() {
        g.row("Toolchain", vec![s("unknown", Dim)]);
    } else {
        let mut l = Vec::new();
        for (i, t) in r.toolchain.iter().enumerate() {
            if i > 0 {
                l.push(sep());
            }
            l.push(s(t, Bold));
        }
        g.row("Toolchain", l);
    }
    match &r.packer {
        Some(p) => {
            let mut lines = vec![vec![s(
                p.name
                    .clone()
                    .unwrap_or_else(|| "possibly packed or encrypted".into()),
                Bad,
            )]];
            lines.extend(p.reasons.iter().map(|why| vec![s(why, Warn)]));
            g.rows("Packer", lines);
        }
        None => {
            let mut l = vec![s("none detected", Good)];
            if let Some(m) = &r.max_entropy {
                l.push(s(
                    format!(" (max entropy {:.2} in {})", m.entropy, m.name),
                    Dim,
                ));
            }
            g.row("Packer", l);
        }
    }
    let c = &r.counts;
    let mut counts = Vec::new();
    let mut count = |n: usize, what: &str| {
        if !counts.is_empty() {
            counts.push(sep());
        }
        counts.push(s(n.to_string(), Num));
        let label = if n == 1 {
            what.strip_suffix('s').unwrap_or(what)
        } else {
            what
        };
        counts.push(s(format!(" {label}"), Dim));
    };
    count(c.sections, "sections");
    if r.format == Format::Elf || r.format == Format::Macho {
        count(c.segments, "segments");
    }
    count(c.symbols, "symbols");
    count(c.imports, "imports");
    count(c.exports, "exports");
    count(c.relocations, "relocs");
    g.row("Counts", counts);
    groups.push(g);

    if !r.warnings.is_empty() {
        let mut g = Group::new(Some("Notes"));
        g.rows(
            "Warning",
            r.warnings.iter().map(|w| vec![s(w, Warn)]).collect(),
        );
        groups.push(g);
    }

    Doc {
        blocks: vec![Block::Panel(Panel {
            title: format!("anyz · {}", r.file_name),
            groups,
        })],
    }
}

/// Linked libraries, with Windows API-set DLLs collapsed and the list capped
/// (the full list belongs to `--imports`).
fn libraries_line(r: &InfoReport) -> Line {
    use Tone::*;
    const MAX: usize = 12;
    let is_api_set = |n: &str| {
        let n = n.to_ascii_lowercase();
        n.starts_with("api-ms-win-") || n.starts_with("ext-ms-win-")
    };
    let api_sets = r.libraries.iter().filter(|l| is_api_set(&l.name)).count();
    let normal: Vec<_> = r
        .libraries
        .iter()
        .filter(|l| !is_api_set(&l.name))
        .collect();
    let mut l = Vec::new();
    for lib in normal.iter().take(MAX) {
        if !l.is_empty() {
            l.push(sep());
        }
        l.push(s(&lib.name, Library));
        if lib.delayed {
            l.push(s(" (delay-load)", Dim));
        }
    }
    if api_sets > 0 {
        if !l.is_empty() {
            l.push(sep());
        }
        l.push(s(format!("{api_sets} api-ms-win-* API sets"), Dim));
    }
    if normal.len() > MAX {
        l.push(sep());
        l.push(s(format!("+{} more", normal.len() - MAX), Dim));
    }
    l
}

fn entry_line(r: &InfoReport) -> Line {
    use Tone::*;
    let Some(loc) = &r.entry else {
        return vec![s("none", Dim)];
    };
    let mut l = vec![s(hex(loc.va), Addr)];
    if let Some(sym) = &loc.symbol {
        l.push(s(format!(" <{sym}>"), Func));
    }
    if let Some(sec) = &loc.section {
        l.push(s(" in ", Dim));
        l.push(s(sec, Section));
    }
    match loc.offset {
        Some(o) => l.push(s(format!(" (file offset {o:#x})"), Dim)),
        None => l.push(s(" (not backed by file data)", Warn)),
    }
    l
}

fn format_rows(r: &InfoReport, g: &mut Group) {
    use Tone::*;
    match &r.details {
        Details::Elf(e) => {
            if let Some(b) = &e.build_id {
                g.row("Build ID", vec![s(b, Hash)]);
            }
            if let Some(so) = &e.soname {
                g.row("SONAME", vec![s(so, Library)]);
            }
            if !e.rpath.is_empty() {
                g.row("RPATH", vec![s(e.rpath.join(":"), Warn)]);
            }
            if !e.runpath.is_empty() {
                g.row("RUNPATH", vec![s(e.runpath.join(":"), Warn)]);
            }
            if let Some(t) = &e.abi_tag {
                g.row("ABI tag", vec![s(t, Normal)]);
            }
            if e.textrel {
                g.row(
                    "TEXTREL",
                    vec![s(
                        "text relocations present (code is patched at load time)",
                        Warn,
                    )],
                );
            }
        }
        Details::Pe(p) => {
            g.row("Compiled", pe_timestamp(p.timestamp, p.reproducible));
            if let Some(pdb) = &p.pdb {
                g.row("PDB", vec![s(&pdb.path, Path)]);
            }
            if let Some(c) = &p.clr {
                let mut l = vec![s(format!("CLR {}", c.runtime_version), Normal)];
                if let Some(v) = &c.metadata_version {
                    l.extend([sep(), s(v, Normal)]);
                }
                if c.requires_32bit {
                    l.extend([sep(), s("32-bit required", Dim)]);
                }
                if c.strong_name_signed {
                    l.extend([sep(), s("strong-name signed", Dim)]);
                }
                g.row(".NET", l);
            }
            if !p.tls_callbacks.is_empty() {
                let mut l = vec![s(format!("{} callback(s): ", p.tls_callbacks.len()), Warn)];
                for (i, cb) in p.tls_callbacks.iter().take(8).enumerate() {
                    if i > 0 {
                        l.push(sep());
                    }
                    l.push(s(hex(*cb), Addr));
                }
                g.row("TLS", l);
            }
            if let Some(o) = &p.overlay {
                g.row(
                    "Overlay",
                    vec![
                        s(human_size(o.size), Warn),
                        s(
                            format!(" of extra data at file offset {:#x}", o.offset),
                            Dim,
                        ),
                    ],
                );
            }
            let checksum = if p.checksum == 0 {
                vec![s("not set", Dim)]
            } else if p.checksum == p.checksum_computed {
                vec![s(hex(u64::from(p.checksum)), Num), s(" (valid)", Good)]
            } else {
                vec![
                    s(hex(u64::from(p.checksum)), Num),
                    s(
                        format!(" (invalid, computed {:#x})", p.checksum_computed),
                        Warn,
                    ),
                ]
            };
            g.row("Checksum", checksum);
            if p.has_rich_header {
                g.row(
                    "Rich header",
                    vec![s(format!("{} tool entries", p.rich.len()), Dim)],
                );
            }
        }
        Details::Macho(m) => {
            if let Some(u) = &m.uuid {
                g.row("UUID", vec![s(u, Hash)]);
            }
            if let Some(f) = &m.fat {
                let mut l = Vec::new();
                for (i, sl) in f.slices.iter().enumerate() {
                    if i > 0 {
                        l.push(sep());
                    }
                    if i == f.selected {
                        l.push(s(&sl.arch, Bold));
                        l.push(s(" (selected)", Good));
                    } else {
                        l.push(s(&sl.arch, Dim));
                    }
                }
                g.row("Slices", l);
            }
            if let Some(cs) = &m.code_signature
                && let Some(id) = &cs.identifier
            {
                let mut l = vec![s(id, Normal)];
                if let Some(t) = &cs.team_id {
                    l.extend([sep(), s(format!("team {t}"), Normal)]);
                }
                g.row("Signed as", l);
            }
            if !m.rpaths.is_empty() {
                g.row("RPATH", vec![s(m.rpaths.join(", "), Warn)]);
            }
        }
        Details::Raw(raw) => {
            if !raw.arch_specified {
                g.row(
                    "Hint",
                    vec![s(
                        "pass --arch <ARCH> (and --base <ADDR>) to treat this blob as code",
                        Dim,
                    )],
                );
            }
        }
    }
}

fn pe_timestamp(ts: u32, reproducible: bool) -> Line {
    use Tone::*;
    if reproducible {
        return vec![
            s("reproducible build", Normal),
            s(format!(" (timestamp field is a hash: {ts:#010x})"), Dim),
        ];
    }
    if ts == 0 {
        return vec![s("not set", Dim)];
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |d| d.as_secs());
    let mut l = vec![s(utc_date(u64::from(ts)), Normal)];
    if u64::from(ts) > now {
        l.push(s(" (in the future: forged or hash-based)", Warn));
    }
    l
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

fn sections(r: &SectionsReport) -> Doc {
    use Align::*;
    use Tone::*;
    let mut blocks = vec![heading("Sections", Some(r.sections.len().to_string()))];
    if r.sections.is_empty() {
        blocks.push(Block::Note(vec![s("no section headers in this file", Dim)]));
        return Doc { blocks };
    }
    let aw = hex_width(r.sections.iter().map(|x| x.addr));
    let ow = hex_width(r.sections.iter().map(|x| x.offset));
    let rows = r
        .sections
        .iter()
        .map(|x| {
            vec![
                s(x.index.to_string(), Dim),
                s(&x.name, Section),
                s(hex_w(x.addr, aw), Addr),
                s(hex_w(x.offset, ow), Offset),
                s(hex(x.size), Num),
                s(
                    hex(x.file_size),
                    if x.file_size == x.size { Num } else { Dim },
                ),
                s(x.perms.to_string(), Perm(x.perms)),
                match x.entropy {
                    Some(e) => s(format!("{e:.2}"), Entropy(e)),
                    None => s("-", Dim),
                },
                s(&x.kind, Dim),
            ]
        })
        .collect();
    blocks.push(Block::Table(Table {
        columns: columns(&[
            ("#", Right),
            ("Name", Left),
            ("Address", Left),
            ("Offset", Left),
            ("Size", Right),
            ("File size", Right),
            ("Perms", Left),
            ("Entropy", Right),
            ("Type", Left),
        ]),
        rows,
    }));
    Doc { blocks }
}

fn segments(r: &SegmentsReport) -> Doc {
    use Align::*;
    use Tone::*;
    let mut blocks = vec![heading("Segments", Some(r.segments.len().to_string()))];
    if let Some(n) = &r.note {
        blocks.push(Block::Note(vec![s(n, Dim)]));
    }
    if r.segments.is_empty() {
        return Doc { blocks };
    }
    let macho = r.format == Format::Macho;
    let aw = hex_width(r.segments.iter().map(|x| x.addr));
    let ow = hex_width(r.segments.iter().map(|x| x.offset));
    let rows = r
        .segments
        .iter()
        .map(|x| {
            let mut secs = x.sections.join(" ");
            if let Some(d) = &x.detail {
                if !secs.is_empty() {
                    secs.push(' ');
                }
                secs.push_str(&format!("[{d}]"));
            }
            let name_tone = if x.name == "LOAD" || macho {
                Bold
            } else {
                Normal
            };
            let last = if macho {
                match x.max_perms {
                    Some(p) => s(p.to_string(), Perm(p)),
                    None => s("-", Dim),
                }
            } else {
                s(hex(x.align), Dim)
            };
            vec![
                s(x.index.to_string(), Dim),
                s(&x.name, name_tone),
                s(hex_w(x.addr, aw), Addr),
                s(hex_w(x.offset, ow), Offset),
                s(hex(x.size), Num),
                s(hex(x.file_size), Num),
                s(x.perms.to_string(), Perm(x.perms)),
                last,
                s(secs, Section),
            ]
        })
        .collect();
    let cols = if macho {
        columns(&[
            ("#", Right),
            ("Name", Left),
            ("Address", Left),
            ("Offset", Left),
            ("VM size", Right),
            ("File size", Right),
            ("Perms", Left),
            ("Max", Left),
            ("Sections", Left),
        ])
    } else {
        columns(&[
            ("#", Right),
            ("Type", Left),
            ("Address", Left),
            ("Offset", Left),
            ("Mem size", Right),
            ("File size", Right),
            ("Perms", Left),
            ("Align", Right),
            ("Sections", Left),
        ])
    };
    blocks.push(Block::Table(Table {
        columns: cols,
        rows,
    }));
    Doc { blocks }
}

fn kind_tone(k: SymKind) -> Tone {
    match k {
        SymKind::Func => Tone::Func,
        SymKind::Object | SymKind::Common => Tone::Object,
        SymKind::Tls => Tone::Tls,
        SymKind::Ifunc => Tone::Ifunc,
        SymKind::File => Tone::FileSym,
        SymKind::Section => Tone::Dim,
        SymKind::NoType => Tone::Normal,
    }
}

fn symbol_name(x: &SymbolRow) -> String {
    let base = x.demangled.as_deref().unwrap_or(&x.name);
    match (&x.version, x.name.contains('@')) {
        (Some(v), false) => format!("{base}@{v}"),
        _ => base.to_string(),
    }
}

fn symbols(r: &SymbolsReport) -> Doc {
    use Align::*;
    use Tone::*;
    let sub = match &r.filter {
        Some(f) => format!("{} of {} matching /{f}/", r.symbols.len(), r.total),
        None => r.total.to_string(),
    };
    let mut blocks = vec![heading("Symbols", Some(sub))];
    if r.symbols.is_empty() {
        let msg = if r.total == 0 {
            "no symbols (stripped binary?) - try --sections, or the entry point"
        } else {
            "no matching symbols"
        };
        blocks.push(Block::Note(vec![s(msg, Dim)]));
        return Doc { blocks };
    }
    let aw = hex_width(r.symbols.iter().filter(|x| x.defined).map(|x| x.addr));
    let rows = r
        .symbols
        .iter()
        .map(|x| {
            let addr = if x.defined && x.kind != SymKind::File {
                s(hex_w(x.addr, aw), Addr)
            } else {
                s("", Dim)
            };
            let bind_tone = match x.bind {
                SymBind::Local | SymBind::Unknown => Dim,
                SymBind::Weak => Warn,
                _ => Normal,
            };
            let section = match &x.section {
                Some(sec) => s(sec, Section),
                None => s("UND", Dim),
            };
            let name_tone = if x.defined { kind_tone(x.kind) } else { Normal };
            vec![
                addr,
                s(
                    if x.size > 0 {
                        x.size.to_string()
                    } else {
                        String::new()
                    },
                    Num,
                ),
                s(x.kind.name(), kind_tone(x.kind)),
                s(x.bind.name(), bind_tone),
                section,
                s(symbol_name(x), name_tone),
            ]
        })
        .collect();
    blocks.push(Block::Table(Table {
        columns: columns(&[
            ("Address", Left),
            ("Size", Right),
            ("Kind", Left),
            ("Bind", Left),
            ("Section", Left),
            ("Name", Left),
        ]),
        rows,
    }));
    Doc { blocks }
}

// ---------------------------------------------------------------------------
// Disassembly, offsets, hex dump
// ---------------------------------------------------------------------------

/// Long symbol names (C++ templates) make listings unreadable; JSON keeps them.
fn short(name: &str, max: usize) -> String {
    if name.chars().count() <= max {
        name.to_string()
    } else {
        name.chars().take(max - 3).collect::<String>() + "..."
    }
}

fn disasm(r: &DisasmReport) -> Doc {
    use Tone::*;
    let syntax = match r.syntax {
        Some(crate::analyzers::disasm::Syntax::Intel) => ", Intel syntax",
        Some(crate::analyzers::disasm::Syntax::Att) => ", AT&T syntax",
        None => "",
    };
    let subtitle = format!(
        "{}{:#x}..{:#x}, {}{}, {} instructions",
        r.function
            .as_deref()
            .map(|f| format!("{}, ", short(f, 60)))
            .unwrap_or_default(),
        r.start,
        r.end,
        r.mode,
        syntax,
        r.instructions.len()
    );
    let mut blocks = vec![heading("Disassembly", Some(subtitle))];
    for n in &r.notes {
        blocks.push(Block::Note(vec![s(n, Warn)]));
    }
    let aw = hex_width(r.instructions.iter().map(|i| i.addr));
    const MAX_BYTES: usize = 8;
    let bw = r
        .instructions
        .iter()
        .map(|i| i.bytes.len().min(MAX_BYTES) * 3)
        .max()
        .unwrap_or(0)
        .saturating_sub(1);
    let mw = r
        .instructions
        .iter()
        .map(|i| i.mnemonic.len())
        .max()
        .unwrap_or(4)
        .clamp(4, 10);
    let mut lines = Vec::new();
    for (n, i) in r.instructions.iter().enumerate() {
        let label = i
            .label
            .as_ref()
            .or(if n == 0 { r.function.as_ref() } else { None });
        if let Some(label) = label {
            if n > 0 {
                lines.push(Vec::new());
            }
            lines.push(vec![
                s(hex_w(i.addr, aw), Addr),
                s(format!(" <{}>:", short(label, 80)), Func),
            ]);
        }
        let mut bytes: Vec<String> = i
            .bytes
            .iter()
            .take(MAX_BYTES)
            .map(|b| format!("{b:02x}"))
            .collect();
        if i.bytes.len() > MAX_BYTES {
            bytes.truncate(MAX_BYTES - 1);
            bytes.push("..".into());
        }
        let mut line = vec![
            s("  ", Normal),
            s(hex_w(i.addr, aw), Addr),
            s("  ", Normal),
            s(format!("{:<bw$}", bytes.join(" ")), Dim),
            s("  ", Normal),
            s(format!("{:<mw$}", i.mnemonic), Insn(i.class)),
        ];
        if !i.operands.is_empty() {
            line.push(s(format!(" {}", i.operands), Normal));
        }
        if let Some(rf) = &i.reference {
            match (rf.kind, &rf.name, &rf.string) {
                // Operand already shows the absolute target (x86, ARM): `call 0x401136 <win>`.
                (RefKind::Code, Some(name), _)
                    if i.operands.contains(&format!("{:#x}", rf.addr)) =>
                {
                    line.push(s(format!(" <{}>", short(name, 60)), Func))
                }
                // PC-relative operand (RISC-V): spell the target out.
                (RefKind::Code, Some(name), _) => {
                    line.push(s(format!("  ; {:#x} ", rf.addr), Dim));
                    line.push(s(format!("<{}>", short(name, 60)), Func));
                }
                (_, _, Some(text)) => {
                    line.push(s(format!("  ; {:#x} ", rf.addr), Dim));
                    line.push(s(text, Str));
                }
                (_, Some(name), None) => {
                    line.push(s(format!("  ; {:#x} <{}>", rf.addr, short(name, 60)), Dim))
                }
                _ => {}
            }
        }
        lines.push(line);
    }
    if lines.is_empty() {
        lines.push(vec![s("no instructions decoded", Dim)]);
    }
    blocks.push(Block::Lines(lines));
    Doc { blocks }
}

fn offsets(r: &OffsetsReport) -> Doc {
    use Tone::*;
    let opt = |v: Option<u64>, tone: Tone| match v {
        Some(v) => vec![s(hex(v), tone)],
        None => vec![s("-", Dim)],
    };
    let mut g = Group::new(None);
    g.row(
        "Input",
        vec![s(&r.expr, Bold), s(format!(" ({})", r.space.name()), Dim)],
    );
    g.row("VA", opt(r.va, Addr));
    g.row("RVA", opt(r.rva, Addr));
    g.row("File offset", opt(r.offset, Offset));
    match &r.section {
        Some(sec) => g.row(
            "Section",
            vec![
                s(&sec.name, Section),
                s(format!(" + {:#x}", sec.delta), Dim),
                s("  ", Normal),
                s(sec.perms.to_string(), Perm(sec.perms)),
            ],
        ),
        None => g.row("Section", vec![s("none", Dim)]),
    }
    if let Some(seg) = &r.segment {
        g.row("Mapping", vec![s(seg, Normal)]);
    }
    if let Some(sym) = &r.symbol {
        g.row("Symbol", vec![s(sym, Func)]);
    }
    if !r.bytes.is_empty() {
        let mut l = Vec::new();
        for (i, b) in r.bytes.iter().enumerate() {
            if i > 0 {
                l.push(s(" ", Normal));
            }
            l.push(s(format!("{b:02x}"), Byte(*b)));
        }
        g.row("Bytes", l);
    }
    g.rows("Note", r.notes.iter().map(|n| vec![s(n, Warn)]).collect());
    Doc {
        blocks: vec![Block::Panel(Panel {
            title: format!("offsets · {}", r.expr),
            groups: vec![g],
        })],
    }
}

fn hexdump(r: &HexdumpReport) -> Doc {
    use Tone::*;
    let place = match r.space {
        Space::Offset => format!("file offset {:#x}", r.offset),
        _ => format!("{:#x} (file offset {:#x})", r.start, r.offset),
    };
    let section = r
        .section
        .as_deref()
        .map(|s| format!(" in {s}"))
        .unwrap_or_default();
    let mut blocks = vec![heading(
        "Hexdump",
        Some(format!("{place}{section}, {} bytes", r.bytes.len())),
    )];
    for n in &r.notes {
        blocks.push(Block::Note(vec![s(n, Warn)]));
    }
    let end = r.start.saturating_add(r.bytes.len() as u64);
    let aw = hex_width([r.start, end].into_iter());
    let mut lines = Vec::new();
    for (row, chunk) in r.bytes.chunks(16).enumerate() {
        let addr = r.start + row as u64 * 16;
        let mut line = vec![s(hex_w(addr, aw), Addr), s("  ", Normal)];
        for i in 0..16 {
            if i == 8 {
                line.push(s(" ", Normal));
            }
            match chunk.get(i) {
                Some(b) => line.push(s(format!("{b:02x} "), Byte(*b))),
                None => line.push(s("   ", Normal)),
            }
        }
        line.push(s(" |", Dim));
        for b in chunk {
            let c = if (0x20..0x7f).contains(b) {
                char::from(*b)
            } else {
                '.'
            };
            line.push(s(c.to_string(), Byte(*b)));
        }
        line.push(s("|", Dim));
        lines.push(line);
    }
    if lines.is_empty() {
        lines.push(vec![s("no bytes", Dim)]);
    }
    blocks.push(Block::Lines(lines));
    Doc { blocks }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(utc_date(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc_date(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc_date(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn sizes_and_numbers() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(16_512), "16.1 KiB");
        assert_eq!(thousands(16_512), "16,512");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000_000), "1,000,000");
        assert_eq!(hex_width([0x401000u64].into_iter()), 6);
        assert_eq!(hex_width([0u64].into_iter()), 4);
        assert_eq!(hex_w(0x1000, 6), "0x001000");
    }
}
