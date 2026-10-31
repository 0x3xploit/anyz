//! `--strings`: printable ASCII (and optionally UTF-16LE) runs, `strings -a` style,
//! over the whole file so overlays, resources and headers are included.

use serde::Serialize;

use crate::model::Binary;

pub const DEFAULT_MIN_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Ascii,
    Utf16,
}

#[derive(Debug, Clone, Serialize)]
pub struct FoundString {
    pub offset: u64,
    pub va: Option<u64>,
    pub section: Option<String>,
    pub encoding: Encoding,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringsReport {
    pub min_len: usize,
    pub utf16: bool,
    pub strings: Vec<FoundString>,
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

/// Byte ranges of printable ASCII runs of at least `min` bytes.
pub(crate) fn ascii_runs(data: &[u8], min: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        match (printable(b), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min {
                    out.push((s, i));
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start
        && data.len() - s >= min
    {
        out.push((s, data.len()));
    }
    out
}

/// Byte ranges of UTF-16LE runs (ASCII-range characters) of at least `min` chars,
/// at either alignment.
pub(crate) fn utf16_runs(data: &[u8], min: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for parity in 0..2 {
        let mut start = None;
        let mut i = parity;
        while i + 1 < data.len() {
            let ok = data[i + 1] == 0 && printable(data[i]);
            match (ok, start) {
                (true, None) => start = Some(i),
                (false, Some(s)) => {
                    if (i - s) / 2 >= min {
                        out.push((s, i));
                    }
                    start = None;
                }
                _ => {}
            }
            i += 2;
        }
        if let Some(s) = start
            && (i - s) / 2 >= min
        {
            out.push((s, i));
        }
    }
    out
}

pub fn analyze(bin: &Binary, min_len: usize, utf16: bool) -> StringsReport {
    let min_len = min_len.max(1);
    let data = bin.bytes();
    let found = |start: usize, value: String, encoding| {
        let off = start as u64;
        FoundString {
            offset: off,
            va: bin.offset_to_va(off).ok(),
            section: bin.section_for_offset(off).map(|s| s.full_name()),
            encoding,
            value,
        }
    };
    let mut strings: Vec<FoundString> = ascii_runs(data, min_len)
        .into_iter()
        .map(|(s, e)| {
            found(
                s,
                data[s..e].iter().map(|&b| char::from(b)).collect(),
                Encoding::Ascii,
            )
        })
        .collect();
    if utf16 {
        strings.extend(utf16_runs(data, min_len).into_iter().map(|(s, e)| {
            let text = data[s..e]
                .chunks_exact(2)
                .map(|c| char::from(c[0]))
                .collect();
            found(s, text, Encoding::Utf16)
        }));
        strings.sort_by_key(|s| s.offset);
    }
    StringsReport {
        min_len,
        utf16,
        strings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_runs_respect_min_len() {
        let d = b"\x00abc\x00defg\x01hijklmn";
        assert_eq!(ascii_runs(d, 4), vec![(5, 9), (10, 17)]);
        assert_eq!(ascii_runs(d, 3), vec![(1, 4), (5, 9), (10, 17)]);
        assert!(ascii_runs(b"", 4).is_empty());
    }

    #[test]
    fn utf16_runs_at_both_alignments() {
        let mut d = vec![0xffu8];
        d.extend("Hello".encode_utf16().flat_map(u16::to_le_bytes));
        d.extend([0, 0]);
        d.extend("Wide".encode_utf16().flat_map(u16::to_le_bytes));
        let runs = utf16_runs(&d, 4);
        assert_eq!(runs.len(), 2, "{runs:?}");
        assert_eq!(runs[0], (1, 11));
        assert!(utf16_runs(&d, 6).is_empty());
    }
}
