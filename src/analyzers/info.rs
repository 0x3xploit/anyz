//! The default "info panel": identification, hashes, linking, mitigations,
//! toolchain and packer heuristics, counts.

use std::collections::HashSet;

use md5::Md5;
use memchr::memmem;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::checksec::{self, Mitigation};
use super::{c_name, entropy, hex, read_uint};
use crate::model::*;

#[derive(Debug, Clone, Serialize)]
pub struct InfoReport {
    pub path: String,
    pub file_name: String,
    pub format: Format,
    /// `ELF64`, `PE32+`, `Mach-O 64-bit`, ...
    pub format_label: String,
    /// `PIE executable`, `shared object`, `DLL`, ...
    pub kind: String,
    pub arch: Arch,
    /// Sub-architecture / ABI detail: `arm64e`, `EABI5 hard-float`, `Thumb-2`, ...
    pub arch_variant: Option<String>,
    pub bits: u8,
    pub endian: Endian,
    pub os: String,
    pub abi: Option<String>,
    pub entry: Option<Location>,
    pub image_base: u64,
    pub file_size: u64,
    pub hashes: Hashes,
    pub linking: Linking,
    pub interpreter: Option<String>,
    pub libraries: Vec<Library>,
    /// `None` when the notion does not apply (raw blobs).
    pub stripped: Option<bool>,
    pub debug_info: bool,
    pub mitigations: Vec<Mitigation>,
    /// Compiler / language / linker guesses, most specific first.
    pub toolchain: Vec<String>,
    pub packer: Option<PackerHint>,
    pub max_entropy: Option<SectionEntropy>,
    pub counts: Counts,
    pub details: Details,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Location {
    pub va: u64,
    pub rva: Option<u64>,
    pub offset: Option<u64>,
    pub section: Option<String>,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Linking {
    Dynamic,
    Static,
    StaticPie,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize)]
pub struct Library {
    pub name: String,
    pub delayed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackerHint {
    /// Identified packer, if a signature matched.
    pub name: Option<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionEntropy {
    pub name: String,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Counts {
    pub sections: usize,
    pub segments: usize,
    pub symbols: usize,
    pub imports: usize,
    pub exports: usize,
    pub relocations: usize,
    pub libraries: usize,
}

pub fn analyze(bin: &Binary) -> InfoReport {
    let section_entropy: Vec<(String, f64, u64)> = bin
        .sections
        .iter()
        .filter(|s| s.file_size > 0 && s.alloc && bin.format != Format::Raw)
        .map(|s| {
            (
                s.full_name(),
                entropy::shannon(bin.section_data(s)),
                s.file_size,
            )
        })
        .collect();
    let max_entropy = section_entropy
        .iter()
        .filter(|(_, _, size)| *size >= 128)
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(name, e, _)| SectionEntropy {
            name: name.clone(),
            entropy: *e,
        });

    InfoReport {
        path: bin.path.display().to_string(),
        file_name: bin.file_name(),
        format: bin.format,
        format_label: format_label(bin),
        kind: kind_label(bin),
        arch: bin.arch.clone(),
        arch_variant: arch_variant(bin),
        bits: bin.bits,
        endian: bin.endian,
        os: bin.os.clone(),
        abi: bin.abi.clone(),
        entry: bin.entry.map(|va| location(bin, va)),
        image_base: bin.image_base,
        file_size: bin.file_size,
        hashes: hashes(bin),
        linking: linking(bin),
        interpreter: bin.interpreter.clone(),
        libraries: libraries(bin),
        stripped: stripped(bin),
        debug_info: debug_info(bin),
        mitigations: checksec::analyze(bin).items,
        toolchain: toolchain(bin),
        packer: packer(bin, &section_entropy),
        max_entropy,
        counts: Counts {
            sections: bin.sections.len(),
            segments: bin.segments.len(),
            symbols: bin.symbols.len(),
            imports: bin.imports.len(),
            exports: bin.exports.len(),
            relocations: bin.relocations.len(),
            libraries: bin.libraries.len(),
        },
        details: bin.details.clone(),
        warnings: bin.warnings.clone(),
    }
}

pub fn location(bin: &Binary, va: u64) -> Location {
    Location {
        va,
        rva: bin.va_to_rva(va).ok(),
        offset: bin.va_to_offset(va).ok(),
        section: bin.section_for_va(va).map(|s| s.full_name()),
        symbol: bin
            .symbols
            .iter()
            .find(|s| {
                s.defined && s.addr == va && matches!(s.kind, SymKind::Func | SymKind::NoType)
            })
            .map(|s| s.display_name().to_string()),
    }
}

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

fn hashes(bin: &Binary) -> Hashes {
    let data = bin.file_bytes();
    let (md5, sha1, sha256) = if data.len() < (8 << 20) {
        (
            hex(&Md5::digest(data)),
            hex(&Sha1::digest(data)),
            hex(&Sha256::digest(data)),
        )
    } else {
        // Large files: one thread per digest over the shared mapping.
        std::thread::scope(|s| {
            let m = s.spawn(|| hex(&Md5::digest(data)));
            let h1 = s.spawn(|| hex(&Sha1::digest(data)));
            let h256 = hex(&Sha256::digest(data));
            (
                m.join().unwrap_or_default(),
                h1.join().unwrap_or_default(),
                h256,
            )
        })
    };
    Hashes {
        md5,
        sha1,
        sha256,
        imphash: imphash(bin),
    }
}

/// pefile-compatible import hash: md5 over `lib.func` pairs in import order.
pub fn imphash(bin: &Binary) -> Option<String> {
    if bin.format != Format::Pe {
        return None;
    }
    let mut parts = Vec::new();
    for imp in bin.imports.iter().filter(|i| !i.delayed) {
        let dll = imp.library.as_deref().unwrap_or("").to_ascii_lowercase();
        let lib = match dll.rsplit_once('.') {
            Some((stem, "dll" | "ocx" | "sys")) => stem.to_string(),
            _ => dll.clone(),
        };
        let func = match (&imp.name, imp.ordinal) {
            (Some(n), _) => n.to_ascii_lowercase(),
            (None, Some(o)) => ordinal_name(&dll, o)
                .map(str::to_ascii_lowercase)
                .unwrap_or_else(|| format!("ord{o}")),
            (None, None) => continue,
        };
        parts.push(format!("{lib}.{func}"));
    }
    (!parts.is_empty()).then(|| hex(&Md5::digest(parts.join(",").as_bytes())))
}

/// Ordinal -> name for the DLLs pefile resolves when computing imphash.
fn ordinal_name(dll: &str, ord: u32) -> Option<&'static str> {
    let table = match dll {
        "ws2_32.dll" | "wsock32.dll" => super::ordinals::WS2_32,
        "oleaut32.dll" => super::ordinals::OLEAUT32,
        _ => return None,
    };
    table
        .binary_search_by_key(&ord, |&(o, _)| o)
        .ok()
        .map(|i| table[i].1)
}

// ---------------------------------------------------------------------------
// Identification
// ---------------------------------------------------------------------------

fn format_label(bin: &Binary) -> String {
    match &bin.details {
        Details::Elf(e) => format!("ELF{}", e.class),
        Details::Pe(p) => if p.pe32_plus { "PE32+" } else { "PE32" }.to_string(),
        Details::Macho(m) => {
            let base = format!("Mach-O {}-bit", if bin.bits == 64 { 64 } else { 32 });
            match &m.fat {
                Some(f) => format!("{base} (fat: {} slices)", f.slices.len()),
                None => base,
            }
        }
        Details::Raw(r) => match &r.magic {
            Some(m) => format!("raw data ({m})"),
            None => "raw data".into(),
        },
    }
}

fn kind_label(bin: &Binary) -> String {
    match &bin.details {
        Details::Elf(e) => match bin.kind {
            FileKind::Executable if e.e_type == 3 => {
                if bin.interpreter.is_none() && e.has_dynamic {
                    "static-pie executable".into()
                } else {
                    "PIE executable".into()
                }
            }
            FileKind::Executable => "executable".into(),
            FileKind::SharedLibrary => "shared object".into(),
            FileKind::Object => "relocatable object".into(),
            FileKind::Core => "core dump".into(),
            _ => format!("type {:#x}", e.e_type),
        },
        Details::Pe(p) => {
            let base = match bin.kind {
                FileKind::SharedLibrary => "DLL",
                FileKind::Driver => "driver",
                FileKind::Object => "COFF object",
                _ if (10..=13).contains(&p.subsystem) => "EFI image",
                _ => "executable",
            };
            match &p.clr {
                Some(c) if c.il_only => format!("{base} (.NET)"),
                Some(_) => format!("{base} (.NET mixed-mode)"),
                None => base.to_string(),
            }
        }
        Details::Macho(m) => match m.filetype {
            1 => "object",
            2 => "executable",
            3 => "fixed VM library",
            4 => "core dump",
            5 => "preloaded executable",
            6 => "dynamic library",
            7 => "dynamic linker",
            8 => "bundle",
            9 => "dylib stub",
            10 => "dSYM companion",
            11 => "kernel extension",
            12 => "kernel fileset",
            _ => "unknown type",
        }
        .to_string(),
        Details::Raw(_) => "blob".into(),
    }
}

fn arch_variant(bin: &Binary) -> Option<String> {
    match &bin.details {
        Details::Macho(m)
            if !matches!(
                m.cpu_name.as_str(),
                "arm64" | "x86_64" | "i386" | "ppc" | "ppc64"
            ) =>
        {
            Some(m.cpu_name.clone())
        }
        Details::Pe(_) if bin.thumb => Some("Thumb-2".into()),
        Details::Elf(e) if bin.arch == Arch::Arm => {
            let eabi = e.flags >> 24;
            let float = if e.flags & 0x400 != 0 {
                " hard-float"
            } else if e.flags & 0x200 != 0 {
                " soft-float"
            } else {
                ""
            };
            (eabi != 0).then(|| format!("EABI{eabi}{float}"))
        }
        Details::Elf(e) if matches!(bin.arch, Arch::Mips | Arch::Mips64) => {
            let isa = match e.flags >> 28 {
                0 => "MIPS-I",
                1 => "MIPS-II",
                2 => "MIPS-III",
                3 => "MIPS-IV",
                4 => "MIPS-V",
                5 => "MIPS32",
                6 => "MIPS64",
                7 => "MIPS32r2",
                8 => "MIPS64r2",
                9 => "MIPS32r6",
                10 => "MIPS64r6",
                _ => return None,
            };
            Some(isa.to_string())
        }
        Details::Elf(e) if matches!(bin.arch, Arch::RiscV32 | Arch::RiscV64) => {
            let float = match e.flags & 0x6 {
                0 => "soft-float",
                2 => "single-float",
                4 => "double-float",
                _ => "quad-float",
            };
            let rvc = if e.flags & 1 != 0 { ", RVC" } else { "" };
            Some(format!("{float}{rvc}"))
        }
        _ => None,
    }
}

fn linking(bin: &Binary) -> Linking {
    match &bin.details {
        Details::Elf(e) => {
            if bin.kind == FileKind::Object || bin.kind == FileKind::Core {
                Linking::NotApplicable
            } else if !e.has_dynamic {
                Linking::Static
            } else if bin.interpreter.is_none() && bin.kind == FileKind::Executable && e.e_type == 3
            {
                Linking::StaticPie
            } else {
                Linking::Dynamic
            }
        }
        Details::Pe(_) | Details::Macho(_) => {
            if bin.kind == FileKind::Object {
                Linking::NotApplicable
            } else if bin.imports.is_empty() && bin.libraries.is_empty() {
                Linking::Static
            } else {
                Linking::Dynamic
            }
        }
        Details::Raw(_) => Linking::NotApplicable,
    }
}

fn libraries(bin: &Binary) -> Vec<Library> {
    let delayed: HashSet<String> = bin
        .imports
        .iter()
        .filter(|i| i.delayed)
        .filter_map(|i| i.library.as_ref().map(|l| l.to_ascii_lowercase()))
        .collect();
    let normal: HashSet<String> = bin
        .imports
        .iter()
        .filter(|i| !i.delayed)
        .filter_map(|i| i.library.as_ref().map(|l| l.to_ascii_lowercase()))
        .collect();
    bin.libraries
        .iter()
        .map(|l| {
            let key = l.to_ascii_lowercase();
            Library {
                name: l.clone(),
                delayed: delayed.contains(&key) && !normal.contains(&key),
            }
        })
        .collect()
}

fn stripped(bin: &Binary) -> Option<bool> {
    match &bin.details {
        Details::Elf(e) => Some(!e.has_symtab),
        Details::Pe(p) => Some(!p.has_coff_symbols),
        Details::Macho(_) => Some(
            !bin.symbols
                .iter()
                .any(|s| s.defined && s.name != "__mh_execute_header" && s.name != "___dso_handle"),
        ),
        Details::Raw(_) => None,
    }
}

fn debug_info(bin: &Binary) -> bool {
    match &bin.details {
        Details::Elf(e) => e.has_debug_info,
        Details::Pe(_) => bin.sections.iter().any(|s| s.name.starts_with(".debug_")),
        Details::Macho(m) => m.has_stabs || bin.segments.iter().any(|s| s.name == "__DWARF"),
        Details::Raw(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Toolchain / language guess
// ---------------------------------------------------------------------------

/// Byte signatures are stored XOR-encoded (decoded at runtime) so anyz's own
/// executable does not contain them verbatim; otherwise anyz would "detect"
/// UPX, PyInstaller, Go, ... when run on itself or on similar tools.
const fn obf<const N: usize>(s: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = s[i] ^ 0xa5;
        i += 1;
    }
    out
}

fn sig(p: &[u8]) -> Vec<u8> {
    p.iter().map(|b| b ^ 0xa5).collect()
}

static SIG_GO_BUILDINF: [u8; 14] = obf(b"\xff Go buildinf:");
static SIG_RUSTC_PATH: [u8; 7] = obf(b"/rustc/");
static SIG_RUST_BACKTRACE: [u8; 14] = obf(b"RUST_BACKTRACE");
static SIG_GCC: [u8; 6] = obf(b"GCC: (");
static SIG_MINGW: [u8; 9] = obf(b"Mingw-w64");
static SIG_MINGW_RT: [u8; 25] = obf(b"Mingw-w64 runtime failure");
static SIG_EMBARCADERO: [u8; 11] = obf(b"Embarcadero");
static SIG_BORLAND: [u8; 7] = obf(b"Borland");
static SIG_NIM_MAIN: [u8; 7] = obf(b"NimMain");
static SIG_NIM_FATAL: [u8; 9] = obf(b"fatal.nim");
static SIG_PYINSTALLER: [u8; 11] = obf(b"PyInstaller");
static SIG_MEIPASS: [u8; 8] = obf(b"_MEIPASS");
static SIG_PYI_COOKIE: [u8; 8] = obf(b"MEI\x0c\x0b\x0a\x0b\x0e");
static SIG_AUTOIT: [u8; 8] = obf(b"AU3!EA06");
static SIG_UPX_MAGIC: [u8; 4] = obf(b"UPX!");
static SIG_UPX_INFO: [u8; 41] = obf(b"This file is packed with the UPX executab");

fn toolchain(bin: &Binary) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let data = bin.bytes();
    let has = |pat: &[u8]| memmem::find(data, &sig(pat)).is_some();
    let macho = bin.format == Format::Macho;
    let section_prefix = |p: &str| bin.sections.iter().any(|s| s.name.starts_with(p));
    let imports: HashSet<&str> = bin
        .imports
        .iter()
        .filter_map(|i| i.name.as_deref())
        .map(|n| c_name(n, macho))
        .collect();
    let lib_has = |needle: &str| {
        bin.libraries
            .iter()
            .any(|l| l.to_ascii_lowercase().contains(needle))
    };
    let elf = bin.elf();
    let pe = bin.pe();

    // --- languages with distinctive runtimes
    if let Some(v) = go_version(bin) {
        push_unique(&mut out, format!("Go {}", v.trim_start_matches("go")));
    } else if section_prefix(".gopclntab")
        || section_prefix("__gopclntab")
        || bin.has_section(".go.buildinfo")
        || elf.is_some_and(|e| e.go_build_id.is_some())
    {
        push_unique(&mut out, "Go".into());
    }
    let rustc = elf.and_then(|e| {
        e.comment.iter().find_map(|c| {
            c.strip_prefix("rustc version ")
                .and_then(|v| v.split_whitespace().next())
                .map(str::to_string)
        })
    });
    if let Some(v) = rustc {
        push_unique(&mut out, format!("Rust {v}"));
    } else if has(&SIG_RUSTC_PATH)
        || has(&SIG_RUST_BACKTRACE)
        || bin
            .symbols
            .iter()
            .take(20_000)
            .any(|s| is_rust_symbol(&s.name))
    {
        push_unique(&mut out, "Rust".into());
    }
    if let Some(clr) = pe.and_then(|p| p.clr.as_ref()) {
        push_unique(
            &mut out,
            match &clr.metadata_version {
                Some(v) => format!(".NET (CLR {v})"),
                None => ".NET".into(),
            },
        );
    }
    if lib_has("msvbvm60") || lib_has("msvbvm50") {
        push_unique(&mut out, "Visual Basic 6".into());
    }
    if pe.is_some()
        && (bin.has_section(".itext") || (bin.has_section("CODE") && bin.has_section("DATA")))
        && (has(&SIG_EMBARCADERO) || has(&SIG_BORLAND))
    {
        push_unique(&mut out, "Delphi / C++Builder".into());
    }
    if bin
        .symbols
        .iter()
        .any(|s| c_name(&s.name, macho) == "NimMain")
        || (has(&SIG_NIM_MAIN) && has(&SIG_NIM_FATAL))
    {
        push_unique(&mut out, "Nim".into());
    }
    if has(&SIG_PYI_COOKIE) || (has(&SIG_PYINSTALLER) && has(&SIG_MEIPASS)) {
        push_unique(&mut out, "Python (PyInstaller bundle)".into());
    }
    if has(&SIG_AUTOIT) {
        push_unique(&mut out, "AutoIt script".into());
    }
    if section_prefix("__swift5") || section_prefix(".swift5") || lib_has("libswiftcore") {
        push_unique(&mut out, "Swift".into());
    }
    if section_prefix("__objc_") || imports.contains("objc_msgSend") {
        push_unique(&mut out, "Objective-C".into());
    }
    let cxx_symbols = bin.symbols.iter().take(50_000).any(|s| {
        (s.name.starts_with("_Z") || s.name.starts_with("__Z")) && !is_rust_symbol(&s.name)
    });
    let cxx_libs = lib_has("libstdc++") || lib_has("libc++") || lib_has("msvcp");
    let msvc_mangled = bin
        .exports
        .iter()
        .any(|e| e.name.as_deref().is_some_and(|n| n.starts_with('?')))
        || bin
            .imports
            .iter()
            .any(|i| i.name.as_deref().is_some_and(|n| n.starts_with('?')));
    if cxx_symbols || cxx_libs || msvc_mangled {
        push_unique(&mut out, "C++".into());
    }

    // --- compilers / linkers
    if let Some(e) = elf {
        for c in &e.comment {
            if let Some(t) = parse_comment(c) {
                push_unique(&mut out, t);
            }
        }
    }
    if !out.iter().any(|t| t.starts_with("GCC"))
        && let Some(pos) = memmem::find(data, &sig(&SIG_GCC))
    {
        let tail = &data[pos..data.len().min(pos + 160)];
        let end = memchr::memchr(0, tail).unwrap_or(tail.len());
        if let Some(t) = parse_comment(&String::from_utf8_lossy(&tail[..end])) {
            let mingw = pe.is_some() && (has(&SIG_MINGW) || t.contains("MSYS2"));
            push_unique(&mut out, if mingw { format!("{t} (MinGW-w64)") } else { t });
        }
    }
    if let Some(p) = pe {
        let (maj, min) = p.linker_version;
        if p.has_rich_header {
            push_unique(
                &mut out,
                match vs_name(maj, min) {
                    Some(vs) => format!("MSVC ({vs}, link {maj}.{min:02})"),
                    None => format!("MSVC (link {maj}.{min:02})"),
                },
            );
        } else if maj == 2 || has(&SIG_MINGW_RT) {
            if !out.iter().any(|t| t.contains("MinGW")) {
                push_unique(&mut out, format!("MinGW-w64 (GNU ld {maj}.{min})"));
            }
        } else if maj == 14 && min == 0 && p.clr.is_none() {
            push_unique(&mut out, "LLVM (lld-link)".into());
        }
    }
    if let Some(m) = bin.macho() {
        for t in &m.build_tools {
            push_unique(&mut out, t.clone());
        }
    }
    out
}

fn push_unique(out: &mut Vec<String>, s: String) {
    if !out.contains(&s) {
        out.push(s);
    }
}

/// `GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0` -> `GCC 11.4.0`, and friends.
fn parse_comment(c: &str) -> Option<String> {
    let c = c.trim();
    if let Some(rest) = c.strip_prefix("GCC: (") {
        let distro = rest.split(')').next().unwrap_or("");
        let ver = rest
            .split_once(')')
            .map(|x| x.1)
            .unwrap_or("")
            .split_whitespace()
            .next()?;
        if !ver.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        let note = if distro.contains("MSYS2") {
            " (MSYS2)"
        } else {
            ""
        };
        return Some(format!("GCC {ver}{note}"));
    }
    if let Some(i) = c.find("clang version ") {
        let ver = c[i + 14..].split_whitespace().next()?;
        let ver = ver.split('-').next().unwrap_or(ver);
        let who = if c.starts_with("Android") {
            " (Android NDK)"
        } else if c.starts_with("Apple") {
            " (Apple)"
        } else {
            ""
        };
        return Some(format!("Clang {ver}{who}"));
    }
    if let Some(rest) = c.strip_prefix("Linker: LLD ") {
        return Some(format!("LLD {}", rest.split_whitespace().next()?));
    }
    if let Some(rest) = c.strip_prefix("mold ") {
        return Some(format!("mold {}", rest.split_whitespace().next()?));
    }
    if c.starts_with("rustc version ") {
        return None; // handled as a language
    }
    if c.contains("Intel(R)") && c.contains("Compiler") {
        return Some(c.to_string());
    }
    None
}

fn vs_name(major: u8, minor: u8) -> Option<&'static str> {
    Some(match (major, minor) {
        (14, m) if m >= 50 => "VS2026",
        (14, m) if m >= 30 => "VS2022",
        (14, m) if m >= 20 => "VS2019",
        (14, m) if m >= 10 => "VS2017",
        (14, _) => "VS2015",
        (12, _) => "VS2013",
        (11, _) => "VS2012",
        (10, _) => "VS2010",
        (9, _) => "VS2008",
        (8, _) => "VS2005",
        (7, 10) => "VS2003",
        (7, _) => "VS2002",
        (6, _) => "VC6",
        _ => return None,
    })
}

/// Rust legacy (`_ZN...17h<16 hex>E`) or v0 (`_R...`) mangling.
fn is_rust_symbol(name: &str) -> bool {
    let n = name
        .strip_prefix('_')
        .filter(|r| r.starts_with("_ZN") || r.starts_with("_R"))
        .unwrap_or(name);
    if let Some(rest) = n.strip_prefix("_R") {
        return rest.starts_with(['N', 'C', 'M', 'X', 'Y', 'I']) && rest.len() > 4;
    }
    if !n.starts_with("_ZN") {
        return false;
    }
    let core = n.split('.').next().unwrap_or(n);
    let Some(body) = core.strip_suffix('E') else {
        return false;
    };
    body.len() > 19 && {
        let tail = &body[body.len() - 19..];
        tail.starts_with("17h") && tail[3..].bytes().all(|b| b.is_ascii_hexdigit())
    }
}

/// Go toolchain version from the build info blob (`\xff Go buildinf:`).
fn go_version(bin: &Binary) -> Option<String> {
    let magic = sig(&SIG_GO_BUILDINF);
    memmem::find_iter(bin.bytes(), &magic)
        .take(16)
        .find_map(|pos| go_version_at(bin, pos))
}

fn go_version_at(bin: &Binary, pos: usize) -> Option<String> {
    let data = bin.bytes();
    let hdr = data.get(pos..pos + 32)?;
    let ptr_size = hdr[14] as usize;
    let flags = hdr[15];
    let raw: &[u8] = if flags & 2 != 0 {
        // Go 1.18+: varint-length-prefixed strings inline after the header.
        let (len, n) = uvarint(data.get(pos + 32..)?)?;
        let start = pos + 32 + n;
        data.get(start..start.checked_add(len as usize)?)?
    } else {
        if ptr_size != 4 && ptr_size != 8 {
            return None;
        }
        let endian = if flags & 1 != 0 {
            Endian::Big
        } else {
            Endian::Little
        };
        let vptr = read_uint(data, pos + 16, ptr_size, endian)?;
        let hdr_off = bin.va_to_offset(vptr).ok()? as usize;
        let sptr = read_uint(data, hdr_off, ptr_size, endian)?;
        let slen = read_uint(data, hdr_off + ptr_size, ptr_size, endian)?;
        let soff = bin.va_to_offset(sptr).ok()? as usize;
        data.get(soff..soff.checked_add(slen as usize)?)?
    };
    let s = std::str::from_utf8(raw).ok()?;
    (s.starts_with("go") && s.len() < 64 && s.bytes().all(|b| b.is_ascii_graphic()))
        .then(|| s.to_string())
}

fn uvarint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    for (i, &byte) in b.iter().enumerate().take(10) {
        v |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Packer heuristics
// ---------------------------------------------------------------------------

const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".UPX0", "UPX"),
    (".UPX1", "UPX"),
    ("UPX!", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    ("ASPack", "ASPack"),
    (".petite", "Petite"),
    ("MPRESS1", "MPRESS"),
    ("MPRESS2", "MPRESS"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    (".nsp2", "NsPack"),
    ("nsp0", "NsPack"),
    ("nsp1", "NsPack"),
    (".themida", "Themida"),
    (".Themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".vmp2", "VMProtect"),
    ("PEC2", "PECompact"),
    ("PEC2TO", "PECompact"),
    ("PECompact2", "PECompact"),
    ("pec1", "PECompact"),
    ("pec2", "PECompact"),
    (".enigma1", "Enigma Protector"),
    (".enigma2", "Enigma Protector"),
    (".perplex", "Perplex PE-Protector"),
    ("FSG!", "FSG"),
    (".RLPack", "RLPack"),
    (".yP", "Y0da Protector"),
    (".y0da", "Y0da Protector"),
    ("kkrunchy", "kkrunchy"),
    ("PELOCKnt", "PELock"),
    (".spack", "Simple Pack"),
    (".taz", "PESpin"),
    (".svkp", "SVKP"),
    (".neolit", "NeoLite"),
    ("ExeS", "ExeStealth"),
    (".MaskPE", "MaskPE"),
    (".ccg", "CCG"),
    (".shrink1", "Shrinker"),
    (".boom", "The Boomerang"),
    (".sforce3", "StarForce"),
    ("ProCrypt", "ProCrypt"),
    (".WWPACK", "WWPack"),
];

/// Sections whose contents are high-entropy by design (resources, compressed
/// metadata, dense RVA tables in very large images) and say nothing about packing.
const NATURALLY_HIGH_ENTROPY: &[&str] = &[".rsrc", ".pdata", ".reloc", ".rustc", ".gnu_debugdata"];

fn packer(bin: &Binary, section_entropy: &[(String, f64, u64)]) -> Option<PackerHint> {
    let mut name: Option<String> = None;
    let mut reasons = Vec::new();
    let mut matched = Vec::new();
    for s in &bin.sections {
        if let Some((_, p)) = PACKER_SECTIONS.iter().find(|(n, _)| *n == s.name) {
            name.get_or_insert_with(|| p.to_string());
            matched.push(s.name.clone());
        }
    }
    if !matched.is_empty() {
        reasons.push(format!("packer section names: {}", matched.join(", ")));
    }
    let data = bin.bytes();
    let head = &data[..data.len().min(0x2000)];
    if bin.format != Format::Raw
        && (memmem::find(head, &sig(&SIG_UPX_MAGIC)).is_some()
            || memmem::find(data, &sig(&SIG_UPX_INFO)).is_some())
    {
        name.get_or_insert_with(|| "UPX".to_string());
        reasons.push("UPX signature in file".into());
    }
    let high: Vec<String> = section_entropy
        .iter()
        .filter(|(n, e, size)| {
            *e > entropy::PACKED_THRESHOLD
                && *size >= 512
                && !NATURALLY_HIGH_ENTROPY.contains(&n.as_str())
        })
        .map(|(n, e, _)| format!("{n} ({e:.2})"))
        .collect();
    if !high.is_empty() {
        reasons.push(format!("high entropy: {}", high.join(", ")));
    }
    if bin.sections.iter().all(|s| s.file_size == 0) && bin.format != Format::Raw {
        let e = entropy::shannon(data);
        if e > entropy::PACKED_THRESHOLD {
            reasons.push(format!("high whole-file entropy ({e:.2})"));
        }
    }
    (name.is_some() || !reasons.is_empty()).then_some(PackerHint { name, reasons })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comment_parsing() {
        assert_eq!(
            parse_comment("GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0").as_deref(),
            Some("GCC 11.4.0")
        );
        assert_eq!(
            parse_comment("GCC: (GNU) 13.2.1 20230801").as_deref(),
            Some("GCC 13.2.1")
        );
        assert_eq!(
            parse_comment("Ubuntu clang version 14.0.0-1ubuntu1.1").as_deref(),
            Some("Clang 14.0.0")
        );
        assert_eq!(
            parse_comment("Android (13691557, based on r522817d) clang version 18.0.4 (https://x)")
                .as_deref(),
            Some("Clang 18.0.4 (Android NDK)")
        );
        assert_eq!(
            parse_comment("Linker: LLD 18.0.4").as_deref(),
            Some("LLD 18.0.4")
        );
        assert_eq!(parse_comment("something else"), None);
    }

    #[test]
    fn rust_symbols() {
        assert!(is_rust_symbol("_ZN4core3fmt5write17h0123456789abcdefE"));
        assert!(is_rust_symbol("__ZN4core3fmt5write17h0123456789abcdefE"));
        assert!(is_rust_symbol("_RNvCs1234_7mycrate3foo"));
        assert!(!is_rust_symbol("_ZN3foo3barEv"));
        assert!(!is_rust_symbol("main"));
    }

    #[test]
    fn varint() {
        assert_eq!(uvarint(&[0x08]), Some((8, 1)));
        assert_eq!(uvarint(&[0x96, 0x01]), Some((150, 2)));
        assert_eq!(uvarint(&[0xff; 12]), None);
    }

    #[test]
    fn imphash_matches_pefile_algorithm() {
        // Two imports: kernel32.dll!GetProcAddress and ws2_32.dll ordinal 115 (WSAStartup).
        let mut b = crate::model::tests::sample();
        b.format = Format::Pe;
        let imp = |lib: &str, name: Option<&str>, ord: Option<u32>| Import {
            name: name.map(str::to_string),
            demangled: None,
            ordinal: ord,
            library: Some(lib.into()),
            version: None,
            slot: None,
            plt: None,
            weak: false,
            delayed: false,
        };
        b.imports = vec![
            imp("KERNEL32.dll", Some("GetProcAddress"), None),
            imp("WS2_32.dll", None, Some(115)),
        ];
        let expected = hex(&Md5::digest(b"kernel32.getprocaddress,ws2_32.wsastartup"));
        assert_eq!(imphash(&b).as_deref(), Some(expected.as_str()));
    }
}
