//! File loading: magic-byte detection and dispatch to the format loaders.
//!
//! Each loader converts goblin's format-specific structures into the unified
//! [`Binary`] model. Nothing outside `loader/` touches goblin.

pub mod elf;
pub mod macho;
pub mod pe;
pub mod raw;

use std::fs::File;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::model::{ArchSpec, Binary, Buffer, Data, SymKind, Symbol};

/// User-supplied loading options.
#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    /// Architecture of a raw blob (`--arch`).
    pub arch: Option<ArchSpec>,
    /// Load address of a raw blob (`--base`).
    pub base: Option<u64>,
    /// Slice of a fat Mach-O to analyse (`--slice`).
    pub slice: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detected {
    Elf,
    Pe,
    Macho,
    MachoFat,
    Raw,
}

/// Identify the container format from its magic bytes.
pub fn detect(bytes: &[u8]) -> Detected {
    if bytes.starts_with(b"\x7fELF") {
        return Detected::Elf;
    }
    if bytes.starts_with(b"MZ") {
        if let Some(pe_off) = read_u32_le(bytes, 0x3c) {
            let pe_off = pe_off as usize;
            if bytes.get(pe_off..pe_off.saturating_add(4)) == Some(b"PE\0\0") {
                return Detected::Pe;
            }
        }
        return Detected::Raw; // plain MS-DOS executable
    }
    match bytes.get(0..4) {
        Some([0xfe, 0xed, 0xfa, 0xce | 0xcf]) | Some([0xce | 0xcf, 0xfa, 0xed, 0xfe]) => {
            Detected::Macho
        }
        // 0xcafebabe is shared with Java class files; those have a version number
        // (>= 45) where a fat header has a small slice count.
        Some([0xca, 0xfe, 0xba, 0xbe]) => match read_u32_be(bytes, 4) {
            Some(n) if (1..=30).contains(&n) => Detected::MachoFat,
            _ => Detected::Raw,
        },
        Some([0xca, 0xfe, 0xba, 0xbf]) => Detected::MachoFat,
        _ => Detected::Raw,
    }
}

/// Memory-map `path` and load it.
pub fn load(path: &Path, opts: &LoadOptions) -> Result<Binary> {
    let meta =
        std::fs::metadata(path).with_context(|| format!("cannot open '{}'", path.display()))?;
    if meta.is_dir() {
        bail!("'{}' is a directory, not a file", path.display());
    }
    if meta.len() == 0 {
        bail!("'{}' is empty (0 bytes)", path.display());
    }
    let file = File::open(path).with_context(|| format!("cannot open '{}'", path.display()))?;
    // SAFETY: the mapping is read-only; concurrent modification of the file by
    // another process is outside our control (same caveat as every mmap-based tool).
    let map = unsafe { memmap2::Mmap::map(&file) }
        .with_context(|| format!("cannot map '{}' into memory", path.display()))?;
    load_data(path.to_path_buf(), Data::new(Buffer::Mapped(map)), opts)
}

/// Load from an in-memory buffer (also used by tests).
pub fn load_data(path: PathBuf, data: Data, opts: &LoadOptions) -> Result<Binary> {
    let kind = detect(data.file());
    let file_len = data.file().len();
    let o = opts.clone();
    let mut bin = guard(move || match kind {
        Detected::Elf => elf::load(path, data),
        Detected::Pe => pe::load(path, data),
        Detected::Macho => macho::load(path, data, None),
        Detected::MachoFat => macho::load_fat(path, data, o.slice.as_deref()),
        Detected::Raw => Ok(raw::load(path, data, &o)),
    })
    .map_err(|e| explain_parse_error(e, file_len))?;
    if kind != Detected::Raw {
        if opts.arch.is_some() {
            bin.warnings.push(format!(
                "--arch only applies to raw blobs; ignored for this {} file",
                bin.format
            ));
        }
        if opts.base.is_some() {
            bin.warnings.push(format!(
                "--base only applies to raw blobs; ignored for this {} file",
                bin.format
            ));
        }
    }
    if kind != Detected::MachoFat && opts.slice.is_some() {
        bin.warnings
            .push("--slice only applies to fat (universal) Mach-O files; ignored".to_string());
    }
    Ok(bin)
}

/// Run an optional, best-effort parsing step (e.g. goblin's Mach-O bind-opcode
/// interpreter) so that a panic in it only loses that piece of data. Runs inside
/// [`guard`], whose silent panic hook is already installed.
pub(crate) fn optional<T>(f: impl FnOnce() -> T) -> Option<T> {
    panic::catch_unwind(AssertUnwindSafe(f)).ok()
}

/// goblin reports truncation as low-level read errors ("type is too big (4)
/// for 0"); say what that means.
fn explain_parse_error(e: anyhow::Error, file_len: usize) -> anyhow::Error {
    let msg = format!("{e:#}");
    const BOUNDS: [&str; 6] = [
        "too big",
        "too short",
        "bad offset",
        "out of bounds",
        "past the end",
        "BufferTooShort",
    ];
    if BOUNDS.iter().any(|b| msg.contains(b)) {
        anyhow!("{msg} (the file is {file_len} bytes and looks truncated or corrupt)")
    } else {
        e
    }
}

/// Run a loader, converting any parser panic into a clean error.
fn guard<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    let debug = std::env::var_os("ANYZ_DEBUG").is_some();
    let prev = (!debug).then(|| {
        let prev = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        prev
    });
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    if let Some(prev) = prev {
        panic::set_hook(prev);
    }
    match result {
        Ok(r) => r,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown cause".into());
            Err(anyhow!(
                "malformed binary: the parser gave up on this file ({msg})"
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers for the format loaders
// ---------------------------------------------------------------------------

pub(crate) fn read_u16(bytes: &[u8], off: usize, le: bool) -> Option<u16> {
    let b: [u8; 2] = bytes.get(off..off.checked_add(2)?)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    })
}

pub(crate) fn read_u32(bytes: &[u8], off: usize, le: bool) -> Option<u32> {
    let b: [u8; 4] = bytes.get(off..off.checked_add(4)?)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

pub(crate) fn read_u64(bytes: &[u8], off: usize, le: bool) -> Option<u64> {
    let b: [u8; 8] = bytes.get(off..off.checked_add(8)?)?.try_into().ok()?;
    Some(if le {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    })
}

pub(crate) fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    read_u32(bytes, off, true)
}

pub(crate) fn read_u32_be(bytes: &[u8], off: usize) -> Option<u32> {
    read_u32(bytes, off, false)
}

/// NUL-terminated string at `off` (at most `max` bytes), lossily decoded.
pub(crate) fn cstr_at(bytes: &[u8], off: usize, max: usize) -> Option<String> {
    let tail = bytes.get(off..)?;
    let tail = &tail[..tail.len().min(max)];
    let end = memchr::memchr(0, tail).unwrap_or(tail.len());
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

/// Fixed-size, NUL-padded name field (Mach-O segment/section names, PE section names).
pub(crate) fn fixed_name(raw: &[u8]) -> String {
    let end = memchr::memchr(0, raw).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

pub(crate) fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Demangle Itanium C++ and Rust (legacy and v0) names.
///
/// Handles the Mach-O extra leading underscore (`__ZN...`) and ELF symbol version
/// suffixes (`name@GLIBC_2.2.5`). Returns `None` when the name is not mangled.
pub fn demangle(raw: &str) -> Option<String> {
    let (base, suffix) = match raw.find('@') {
        Some(i) if i > 0 => raw.split_at(i),
        _ => (raw, ""),
    };
    let base = match base.strip_prefix('_') {
        Some(rest) if rest.starts_with("_Z") || rest.starts_with("_R") => rest,
        _ => base,
    };
    if !(base.starts_with("_Z") || base.starts_with("_R")) {
        return None;
    }
    if (base.starts_with("_R") || base.starts_with("_ZN"))
        && let Ok(d) = rustc_demangle::try_demangle(base)
    {
        let s = format!("{d:#}");
        if s != base {
            return Some(s + suffix);
        }
    }
    if base.starts_with("_Z") {
        // cpp_demangle's default recursion limits are what keep hostile names
        // from exhausting the stack; don't raise them.
        if let Ok(sym) = cpp_demangle::Symbol::new(base.as_bytes())
            && let Ok(s) = sym.demangle()
        {
            return Some(s + suffix);
        }
    }
    None
}

/// Fill in sizes for defined code/data symbols that have none (Mach-O, COFF),
/// using the distance to the next symbol in the same section or the section end.
/// `section_range` maps a section name to its `[start, end)` VA range; symbols
/// outside their section's range (e.g. `__mh_execute_header`) are left alone.
pub(crate) fn estimate_sizes(
    symbols: &mut [Symbol],
    section_range: impl Fn(&str) -> Option<(u64, u64)>,
) {
    let range_of = |s: &Symbol| s.section.as_deref().and_then(&section_range);
    let mut idx: Vec<usize> = (0..symbols.len())
        .filter(|&i| {
            let s = &symbols[i];
            s.defined
                && !matches!(s.kind, SymKind::File | SymKind::Section)
                && range_of(s).is_some_and(|(start, end)| s.addr >= start && s.addr < end)
        })
        .collect();
    idx.sort_by(|&a, &b| {
        (symbols[a].section.as_deref(), symbols[a].addr)
            .cmp(&(symbols[b].section.as_deref(), symbols[b].addr))
    });
    for (pos, &i) in idx.iter().enumerate() {
        if symbols[i].size != 0 {
            continue;
        }
        let sec = symbols[i].section.clone();
        let addr = symbols[i].addr;
        let next = idx[pos + 1..]
            .iter()
            .map(|&j| &symbols[j])
            .take_while(|s| s.section == sec)
            .map(|s| s.addr)
            .find(|&a| a > addr);
        let end = next.or_else(|| range_of(&symbols[i]).map(|r| r.1));
        if let Some(end) = end
            && end > addr
        {
            symbols[i].size = end - addr;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_formats() {
        assert_eq!(detect(b"\x7fELF\x02\x01\x01"), Detected::Elf);
        assert_eq!(detect(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0]), Detected::Macho);
        assert_eq!(detect(&[0xfe, 0xed, 0xfa, 0xce]), Detected::Macho);
        assert_eq!(
            detect(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]),
            Detected::MachoFat
        );
        // Java class file (major version 52)
        assert_eq!(
            detect(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34]),
            Detected::Raw
        );
        assert_eq!(detect(b"MZ\x90\x00"), Detected::Raw);
        assert_eq!(detect(b"hello"), Detected::Raw);
        assert_eq!(detect(b""), Detected::Raw);
    }

    #[test]
    fn detects_pe_via_e_lfanew() {
        let mut v = vec![0u8; 0x100];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c] = 0x80;
        v[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(detect(&v), Detected::Pe);
        v[0x3c] = 0xff; // e_lfanew past the end
        v[0x3d] = 0xff;
        assert_eq!(detect(&v), Detected::Raw);
    }

    #[test]
    fn demangles_cpp_and_rust() {
        assert_eq!(demangle("_ZN3foo3barEv").as_deref(), Some("foo::bar()"));
        assert_eq!(demangle("__ZN3foo3barEv").as_deref(), Some("foo::bar()"));
        assert_eq!(
            demangle("_ZN4core3fmt5write17h0123456789abcdefE").as_deref(),
            Some("core::fmt::write")
        );
        assert_eq!(
            demangle("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev@GLIBCXX_3.4.21")
                .as_deref(),
            Some(
                "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()@GLIBCXX_3.4.21"
            )
        );
        assert_eq!(demangle("main"), None);
        assert_eq!(demangle("_start"), None);
        assert_eq!(demangle("_Zgarbage"), None);
    }

    #[test]
    fn cstr_and_names() {
        assert_eq!(cstr_at(b"abc\0def", 0, 64).as_deref(), Some("abc"));
        assert_eq!(cstr_at(b"abc", 1, 64).as_deref(), Some("bc"));
        assert_eq!(cstr_at(b"abc", 9, 64), None);
        assert_eq!(fixed_name(b"__TEXT\0\0\0\0"), "__TEXT");
        assert_eq!(hex_string(&[0xde, 0xad, 0x01]), "dead01");
    }
}
