//! `--offsets`: one address in every address space, with its context.

use anyhow::Result;
use serde::Serialize;

use super::{Names, serialize_hex};
use crate::addr::{self, Space};
use crate::model::{AddrError, Binary, Perms};

#[derive(Debug, Clone, Serialize)]
pub struct SectionHit {
    pub name: String,
    pub start: u64,
    /// Distance from the section start.
    pub delta: u64,
    pub perms: Perms,
}

#[derive(Debug, Clone, Serialize)]
pub struct OffsetsReport {
    pub expr: String,
    pub space: Space,
    pub va: Option<u64>,
    pub rva: Option<u64>,
    pub offset: Option<u64>,
    pub section: Option<SectionHit>,
    pub segment: Option<String>,
    pub symbol: Option<String>,
    /// First bytes at the location (file-backed only).
    #[serde(serialize_with = "serialize_hex")]
    pub bytes: Vec<u8>,
    pub notes: Vec<String>,
}

pub fn analyze(bin: &Binary, expr: &str) -> Result<OffsetsReport> {
    let loc = addr::resolve(bin, expr)?;
    let names = Names::new(bin);
    let mut notes = Vec::new();

    let section = loc
        .va
        .and_then(|va| bin.section_for_va(va).map(|s| (s, va - s.addr)))
        .or_else(|| {
            loc.offset
                .and_then(|o| bin.section_for_offset(o).map(|s| (s, o - s.offset)))
        })
        .map(|(s, delta)| SectionHit {
            name: s.full_name(),
            start: s.addr,
            delta,
            perms: s.perms,
        });
    let region = loc.va.and_then(|va| bin.region_for_va(va));
    let segment = region.map(|r| r.name.clone());

    match (loc.va, loc.offset) {
        (Some(va), None) => match bin.va_to_offset(va) {
            Err(e @ AddrError::NoFileBacking { .. }) => notes.push(e.to_string()),
            Err(_) => notes.push(
                loc.require_offset(bin)
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| format!("{va:#x} is not mapped")),
            ),
            Ok(_) => {}
        },
        (None, Some(off)) => notes.push(
            bin.offset_to_va(off)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default(),
        ),
        _ => {}
    }
    let bytes = loc
        .offset
        .map(|o| crate::model::clamp_slice(bin.bytes(), o, 16).to_vec())
        .unwrap_or_default();
    Ok(OffsetsReport {
        expr: loc.expr.clone(),
        space: loc.space,
        va: loc.va,
        rva: loc.rva,
        offset: loc.offset,
        section,
        segment,
        symbol: loc.va.and_then(|va| names.describe(va)),
        bytes,
        notes,
    })
}
