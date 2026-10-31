//! `--hexdump`: bytes at an address (VA, RVA or file offset).

use anyhow::{Result, anyhow, bail};
use serde::Serialize;

use super::serialize_hex;
use crate::addr::{self, Space};
use crate::model::{Binary, clamp_slice};

pub const DEFAULT_LEN: u64 = 256;
const MAX_LEN: u64 = 16 << 20;

#[derive(Debug, Clone, Serialize)]
pub struct HexdumpReport {
    pub expr: String,
    /// Address space used for the address column (file offsets for `off:`).
    pub space: Space,
    /// Address of the first byte, in `space` (a VA for `rva:` input).
    pub start: u64,
    /// File offset of the first byte.
    pub offset: u64,
    #[serde(serialize_with = "serialize_hex")]
    pub bytes: Vec<u8>,
    pub section: Option<String>,
    pub notes: Vec<String>,
}

pub fn analyze(bin: &Binary, expr: &str, len: Option<&str>) -> Result<HexdumpReport> {
    let loc = addr::resolve(bin, expr)?;
    let want = match len {
        Some(l) => addr::parse_number(l).ok_or_else(|| anyhow!("invalid hexdump length '{l}'"))?,
        None => DEFAULT_LEN,
    };
    if want == 0 {
        bail!("hexdump length must be greater than zero");
    }
    let mut notes = Vec::new();
    let want = if want > MAX_LEN {
        notes.push(format!("length capped at {} MiB", MAX_LEN >> 20));
        MAX_LEN
    } else {
        want
    };
    let (space, start, offset, bytes) = match loc.space {
        Space::Offset => {
            let off = loc.value;
            (Space::Offset, off, off, clamp_slice(bin.bytes(), off, want))
        }
        Space::Va | Space::Rva => {
            let va = loc.require_va(bin)?;
            let off = loc.require_offset(bin)?;
            let data = bin
                .bytes_at_va(va, want)
                .map_err(|e| anyhow!("{}: {e}", loc.expr))?;
            (Space::Va, va, off, data)
        }
    };
    if (bytes.len() as u64) < want {
        notes.push(match space {
            Space::Offset => format!("end of file after {} bytes", bytes.len()),
            _ => format!("end of the file-backed mapping after {} bytes", bytes.len()),
        });
    }
    let section = match space {
        Space::Offset => bin.section_for_offset(offset),
        _ => bin.section_for_va(start),
    }
    .map(|s| s.full_name());
    Ok(HexdumpReport {
        expr: loc.expr,
        space,
        start,
        offset,
        bytes: bytes.to_vec(),
        section,
        notes,
    })
}
