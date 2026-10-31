//! `--find`: search the file for a string or a byte pattern with wildcards.
//!
//! * `de ad ?? ef`, `0xdeadbeef`, `hex:4883ec??` - bytes (`??` matches any byte)
//! * `str:cafe` or anything else - the literal text
//! * `wide:Software` - the text as UTF-16LE

use anyhow::{Result, bail};
use serde::Serialize;

use super::{Names, serialize_hex};
use crate::model::{Binary, clamp_slice};

const MAX_MATCHES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternKind {
    Hex,
    String,
    Utf16,
}

#[derive(Debug, Clone, Serialize)]
pub struct Match {
    pub offset: u64,
    pub va: Option<u64>,
    pub section: Option<String>,
    /// Symbol containing the match (`main+0x20`), if any.
    pub symbol: Option<String>,
    /// The matched bytes plus a little trailing context.
    #[serde(serialize_with = "serialize_hex")]
    pub context: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindReport {
    pub pattern: String,
    pub kind: PatternKind,
    /// Pattern length in bytes.
    pub length: usize,
    pub total: usize,
    pub truncated: bool,
    pub matches: Vec<Match>,
}

/// Bytes to search for; `None` entries are wildcards.
pub fn parse_pattern(input: &str) -> Result<(PatternKind, Vec<Option<u8>>)> {
    let (kind, body) = if let Some(rest) = input.strip_prefix("hex:") {
        (PatternKind::Hex, rest)
    } else if let Some(rest) = input.strip_prefix("str:") {
        (PatternKind::String, rest)
    } else if let Some(rest) = input.strip_prefix("wide:") {
        (PatternKind::Utf16, rest)
    } else if looks_like_hex(input) {
        (PatternKind::Hex, input)
    } else {
        (PatternKind::String, input)
    };
    let bytes: Vec<Option<u8>> = match kind {
        PatternKind::Hex => parse_hex(body)?,
        PatternKind::String => body.bytes().map(Some).collect(),
        PatternKind::Utf16 => body
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .map(Some)
            .collect(),
    };
    if bytes.is_empty() {
        bail!("empty search pattern");
    }
    if bytes.iter().all(Option::is_none) {
        bail!("the pattern must contain at least one non-wildcard byte");
    }
    Ok((kind, bytes))
}

/// `de ad ?? ef` (space-separated byte tokens) or `0x...`; a bare word such as
/// `cafe` stays a string unless written as `hex:cafe`.
fn looks_like_hex(s: &str) -> bool {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return !h.is_empty()
            && h.len() % 2 == 0
            && h.bytes().all(|b| b.is_ascii_hexdigit() || b == b'?');
    }
    let tokens: Vec<&str> = t.split_whitespace().collect();
    tokens.len() >= 2
        && tokens
            .iter()
            .all(|tok| tok.len() == 2 && tok.bytes().all(|b| b.is_ascii_hexdigit() || b == b'?'))
}

fn parse_hex(body: &str) -> Result<Vec<Option<u8>>> {
    let compact: String = body
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if !compact.len().is_multiple_of(2) {
        bail!("hex pattern '{body}' has an odd number of digits");
    }
    compact
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let tok = std::str::from_utf8(pair).unwrap_or("");
            if tok == "??" {
                Ok(None)
            } else {
                u8::from_str_radix(tok, 16)
                    .map(Some)
                    .map_err(|_| anyhow::anyhow!("'{tok}' is not a hex byte (use ?? for any byte)"))
            }
        })
        .collect()
}

/// Offsets of every match (overlapping matches included).
pub fn search(data: &[u8], pat: &[Option<u8>], limit: usize) -> (Vec<usize>, usize) {
    let mut hits = Vec::new();
    let mut total = 0;
    if pat.is_empty() || data.len() < pat.len() {
        return (hits, 0);
    }
    if pat.iter().all(Option::is_some) {
        let needle: Vec<u8> = pat.iter().flatten().copied().collect();
        for pos in memchr::memmem::find_iter(data, &needle) {
            total += 1;
            if hits.len() < limit {
                hits.push(pos);
            }
        }
        return (hits, total);
    }
    // Anchor on the first fixed byte, then verify the rest.
    let (anchor, byte) = pat
        .iter()
        .enumerate()
        .find_map(|(i, b)| b.map(|b| (i, b)))
        .expect("pattern has a fixed byte");
    for p in memchr::memchr_iter(byte, data) {
        let Some(start) = p.checked_sub(anchor) else {
            continue;
        };
        let Some(window) = data.get(start..start + pat.len()) else {
            continue;
        };
        if window
            .iter()
            .zip(pat)
            .all(|(b, want)| want.is_none_or(|w| w == *b))
        {
            total += 1;
            if hits.len() < limit {
                hits.push(start);
            }
        }
    }
    (hits, total)
}

pub fn analyze(bin: &Binary, pattern: &str) -> Result<FindReport> {
    let (kind, pat) = parse_pattern(pattern)?;
    let names = Names::new(bin);
    let data = bin.bytes();
    let (hits, total) = search(data, &pat, MAX_MATCHES);
    let matches = hits
        .into_iter()
        .map(|off| {
            let off = off as u64;
            let va = bin.offset_to_va(off).ok();
            Match {
                offset: off,
                va,
                section: bin.section_for_offset(off).map(|s| s.full_name()),
                symbol: va.and_then(|v| names.describe(v)),
                context: clamp_slice(data, off, (pat.len() as u64).max(16)).to_vec(),
            }
        })
        .collect();
    Ok(FindReport {
        pattern: pattern.to_string(),
        kind,
        length: pat.len(),
        total,
        truncated: total > MAX_MATCHES,
        matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_kinds() {
        assert_eq!(parse_pattern("de ad ?? ef").unwrap().0, PatternKind::Hex);
        assert_eq!(
            parse_pattern("de ad ?? ef").unwrap().1,
            vec![Some(0xde), Some(0xad), None, Some(0xef)]
        );
        assert_eq!(parse_pattern("0x7f454c46").unwrap().1.len(), 4);
        assert_eq!(parse_pattern("cafe").unwrap().0, PatternKind::String);
        assert_eq!(
            parse_pattern("hex:cafe").unwrap().1,
            vec![Some(0xca), Some(0xfe)]
        );
        assert_eq!(parse_pattern("/bin/sh").unwrap().0, PatternKind::String);
        assert_eq!(
            parse_pattern("wide:AB").unwrap().1,
            vec![Some(b'A'), Some(0), Some(b'B'), Some(0)]
        );
        assert!(parse_pattern("hex:abc").is_err());
        assert!(parse_pattern("?? ??").is_err());
        assert!(parse_pattern("hex:zz").is_err());
    }

    #[test]
    fn search_with_and_without_wildcards() {
        let data = b"xxdeadbeefxxdeXXbeef";
        let pat: Vec<Option<u8>> = b"beef".iter().map(|&b| Some(b)).collect();
        assert_eq!(search(data, &pat, 10), (vec![6, 16], 2));
        let pat = vec![Some(b'd'), Some(b'e'), None, None, Some(b'b')];
        assert_eq!(search(data, &pat, 10), (vec![2, 12], 2));
        assert_eq!(search(data, &pat, 1), (vec![2], 2));
        let pat = vec![None, Some(b'x')];
        assert_eq!(search(b"axbx", &pat, 10), (vec![0, 2], 2));
    }
}
