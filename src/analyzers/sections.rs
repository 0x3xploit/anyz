//! Section and segment tables with permissions and entropy.

use serde::Serialize;

use super::entropy;
use crate::model::*;

#[derive(Debug, Clone, Serialize)]
pub struct SectionRow {
    pub index: usize,
    pub name: String,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub file_size: u64,
    pub perms: Perms,
    pub kind: String,
    /// Shannon entropy of the file-backed bytes (`None` for .bss-like sections).
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionsReport {
    pub format: Format,
    pub sections: Vec<SectionRow>,
}

pub fn sections(bin: &Binary) -> SectionsReport {
    let sections = bin
        .sections
        .iter()
        .map(|s| {
            let data = bin.section_data(s);
            SectionRow {
                index: s.index,
                name: s.full_name(),
                addr: s.addr,
                offset: s.offset,
                size: s.size,
                file_size: s.file_size,
                perms: s.perms,
                kind: s.kind.clone(),
                entropy: (!data.is_empty()).then(|| entropy::shannon(data)),
            }
        })
        .collect();
    SectionsReport {
        format: bin.format,
        sections,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SegmentRow {
    pub index: usize,
    pub name: String,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub file_size: u64,
    pub perms: Perms,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_perms: Option<Perms>,
    pub align: u64,
    /// Sections mapped by this segment.
    pub sections: Vec<String>,
    /// Extra information, e.g. the interpreter path for PT_INTERP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SegmentsReport {
    pub format: Format,
    pub segments: Vec<SegmentRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn segments(bin: &Binary) -> SegmentsReport {
    const PT_INTERP: u32 = 3;
    const PT_TLS: u32 = 7;
    let note = match bin.format {
        Format::Pe => {
            Some("PE images have no segments; sections are mapped directly (see --sections)".into())
        }
        Format::Raw => Some("raw blobs have no segments".into()),
        _ if bin.segments.is_empty() => Some("no program headers / segments".into()),
        _ => None,
    };
    let segments = bin
        .segments
        .iter()
        .map(|seg| {
            let sections = bin
                .sections
                .iter()
                .filter(|s| match bin.format {
                    Format::Macho => s.segment.as_deref() == Some(seg.name.as_str()),
                    _ => {
                        let in_range = s.alloc
                            && s.size > 0
                            && seg.vsize > 0
                            && s.addr >= seg.vaddr
                            && s.addr - seg.vaddr < seg.vsize
                            && s.addr.saturating_add(s.size) <= seg.vaddr.saturating_add(seg.vsize);
                        // .tbss occupies no address space outside PT_TLS (readelf rule).
                        in_range && !(s.tls && s.file_size == 0 && seg.kind != PT_TLS)
                    }
                })
                .map(|s| s.full_name())
                .collect();
            let detail = match (bin.format, seg.kind) {
                (Format::Elf, PT_INTERP) => bin.interpreter.clone(),
                _ => None,
            };
            let data = clamp_slice(bin.bytes(), seg.offset, seg.file_size);
            SegmentRow {
                index: seg.index,
                name: seg.name.clone(),
                addr: seg.vaddr,
                offset: seg.offset,
                size: seg.vsize,
                file_size: seg.file_size,
                perms: seg.perms,
                max_perms: seg.max_perms,
                align: seg.align,
                sections,
                detail,
                entropy: (!data.is_empty()).then(|| entropy::shannon(data)),
            }
        })
        .collect();
    SegmentsReport {
        format: bin.format,
        segments,
        note,
    }
}
