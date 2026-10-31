//! Shannon entropy helpers (bits per byte, 0.0 ..= 8.0).

/// Entropy above which data is very likely compressed or encrypted.
pub const PACKED_THRESHOLD: f64 = 7.2;

pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    // Four interleaved histograms avoid store-to-load stalls on runs of equal bytes.
    let mut h = [[0u64; 256]; 4];
    let mut chunks = data.chunks_exact(4);
    for c in chunks.by_ref() {
        h[0][c[0] as usize] += 1;
        h[1][c[1] as usize] += 1;
        h[2][c[2] as usize] += 1;
        h[3][c[3] as usize] += 1;
    }
    for &b in chunks.remainder() {
        h[0][b as usize] += 1;
    }
    let len = data.len() as f64;
    let e: f64 = (0..256)
        .map(|i| h[0][i] + h[1][i] + h[2][i] + h[3][i])
        .filter(|&c| c > 0)
        .map(|c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum();
    // A single repeated byte yields -0.0 (and f64::max may keep the sign).
    if e > 0.0 { e } else { 0.0 }
}

use serde::Serialize;

use crate::model::{Binary, Perms};

/// Number of blocks in the whole-file entropy profile.
const PROFILE_BLOCKS: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct SectionEntropyRow {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub perms: Perms,
    /// `None` for sections without file data (.bss).
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntropyReport {
    pub file_size: u64,
    pub file_entropy: f64,
    /// Entropy of consecutive `block_size`-byte blocks of the file.
    pub block_size: u64,
    pub blocks: Vec<f64>,
    pub sections: Vec<SectionEntropyRow>,
    pub threshold: f64,
}

pub fn analyze(bin: &Binary) -> EntropyReport {
    let data = bin.bytes();
    let block_size = (data.len().div_ceil(PROFILE_BLOCKS)).max(64);
    let blocks = data.chunks(block_size).map(shannon).collect();
    let sections = bin
        .sections
        .iter()
        .map(|s| {
            let bytes = bin.section_data(s);
            SectionEntropyRow {
                name: s.full_name(),
                offset: s.offset,
                size: s.file_size,
                perms: s.perms,
                entropy: (!bytes.is_empty()).then(|| shannon(bytes)),
            }
        })
        .collect();
    EntropyReport {
        file_size: data.len() as u64,
        file_entropy: shannon(data),
        block_size: block_size as u64,
        blocks,
        sections,
        threshold: PACKED_THRESHOLD,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon(&[]), 0.0);
        assert_eq!(shannon(&[0x41; 1000]), 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((shannon(&all) - 8.0).abs() < 1e-9);
        let two: Vec<u8> = (0..1000).map(|i| (i % 2) as u8).collect();
        assert!((shannon(&two) - 1.0).abs() < 1e-9);
    }
}
