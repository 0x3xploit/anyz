//! `--xrefs`: naive cross-references found by sweeping every executable section
//! and collecting instructions whose branch or data target hits the address.

use anyhow::{Result, bail};
use serde::Serialize;

use super::Names;
use super::disasm::{Engine, InsnClass, RefKind, Syntax, code_chunks};
use crate::addr;
use crate::model::{Binary, SymKind};

const MAX_REFS: usize = 5_000;

#[derive(Debug, Clone, Serialize)]
pub struct Xref {
    pub addr: u64,
    /// Function containing the referencing instruction.
    pub function: Option<String>,
    pub kind: RefKind,
    pub class: InsnClass,
    pub mnemonic: String,
    pub operands: String,
    /// Exact address referenced (inside the target range).
    pub target: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct XrefsReport {
    pub expr: String,
    pub target: u64,
    pub name: Option<String>,
    /// Address ranges searched for (the address itself, an import's stub and
    /// slot, or a whole sized data object).
    pub ranges: Vec<(u64, u64)>,
    pub total: usize,
    pub refs: Vec<Xref>,
    pub scanned: Vec<String>,
    pub notes: Vec<String>,
}

pub fn analyze(bin: &Binary, expr: &str) -> Result<XrefsReport> {
    if bin.arch.is_unknown() {
        bail!("the architecture of this file is unknown; pass --arch <ARCH> to scan a raw blob");
    }
    let loc = addr::resolve(bin, expr)?;
    let va = loc.require_va(bin)?;
    let names = Names::new(bin);

    let mut ranges = vec![(va, va + 1)];
    if let Some(sym) = &loc.symbol
        && matches!(sym.kind, SymKind::Object | SymKind::Tls | SymKind::Common)
        && sym.size > 1
    {
        ranges[0] = (sym.addr, sym.addr.saturating_add(sym.size));
    }
    // An import is reached through its stub and/or its pointer slot.
    let base_expr = expr
        .trim()
        .trim_start_matches("sym.imp.")
        .trim_start_matches("imp.");
    for imp in &bin.imports {
        let named = imp.name.as_deref().is_some_and(|n| {
            n == base_expr
                || n.split('@').next() == Some(base_expr)
                || n.strip_prefix('_') == Some(base_expr)
        });
        if named || imp.plt == Some(va) || imp.slot == Some(va) {
            for a in [imp.plt, imp.slot].into_iter().flatten() {
                if !ranges.iter().any(|r| r.0 == a) {
                    ranges.push((a, a + 1));
                }
            }
        }
    }
    // Shared libraries call their own exported (preemptible) functions through
    // the PLT too: follow PLT entries for the symbol at the target address.
    if let Some(elf) = bin.elf() {
        let at_target: Vec<&str> = bin
            .symbols
            .iter()
            .filter(|s| s.defined && s.addr == va)
            .map(|s| s.name.split('@').next().unwrap_or(&s.name))
            .collect();
        for p in &elf.plt {
            if p.name == base_expr
                || at_target.contains(&p.name.as_str())
                || p.addr == va
                || p.slot == va
            {
                for a in [p.addr, p.slot] {
                    if !ranges.iter().any(|r| r.0 == a) {
                        ranges.push((a, a + 1));
                    }
                }
            }
        }
    }
    let hit = |t: u64| ranges.iter().any(|&(lo, hi)| t >= lo && t < hi);

    let chunks = code_chunks(bin);
    let mut notes = Vec::new();
    if chunks.is_empty() {
        notes.push("no executable code found".into());
    }
    let mut refs = Vec::new();
    let mut total = 0usize;
    let mut scanned: Vec<String> = Vec::new();
    let mut engines: [Option<Engine>; 2] = [None, None];
    for (start, data, thumb, label) in &chunks {
        let slot = usize::from(*thumb);
        if engines[slot].is_none() {
            engines[slot] = Some(Engine::new(bin, *thumb, Syntax::Intel)?);
        }
        let engine = engines[slot].as_ref().expect("engine just created");
        if !scanned.contains(label) {
            scanned.push(label.clone());
        }
        engine.sweep(data, *start, usize::MAX, |d| {
            let found = match (d.branch, d.data) {
                (Some(t), _) if hit(t) => Some((t, RefKind::Code)),
                (_, Some((t, kind))) if hit(t) => Some((t, kind)),
                _ => None,
            };
            if let Some((target, kind)) = found {
                total += 1;
                if refs.len() < MAX_REFS {
                    refs.push(Xref {
                        addr: d.addr,
                        function: names.describe(d.addr),
                        kind,
                        class: d.class,
                        mnemonic: d.mnemonic.to_string(),
                        operands: d.operands.to_string(),
                        target,
                    });
                }
            }
            true
        });
    }
    if total > MAX_REFS {
        notes.push(format!(
            "showing the first {MAX_REFS} of {total} references"
        ));
    }
    if bin.format == crate::model::Format::Raw || bin.symbols.is_empty() {
        notes.push(
            "linear sweep: data embedded in code can produce spurious or missed references".into(),
        );
    }
    Ok(XrefsReport {
        expr: loc.expr.clone(),
        target: va,
        name: names.describe(va),
        ranges,
        total,
        refs,
        scanned,
        notes,
    })
}
