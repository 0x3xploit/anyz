//! Mach-O loader (goblin) -> unified model, including fat (universal) binaries.
//!
//! Segment and section headers are read directly from the load commands so the
//! `reserved1/reserved2` fields (indirect symbol table indices, stub sizes) are
//! available; goblin does not expose them.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use goblin::mach::MachO;
use goblin::mach::load_command::CommandVariant;

use super::{Detected, cstr_at, demangle, detect, fixed_name, read_u32, read_u32_be, read_u64};
use crate::model::*;

const MH_TWOLEVEL: u32 = 0x80;
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_PEXT: u8 = 0x10;
const N_UNDF: u8 = 0x0;
const N_ABS: u8 = 0x2;
const N_SECT: u8 = 0xe;
const N_WEAK_REF: u16 = 0x40;
const N_WEAK_DEF: u16 = 0x80;
const N_ARM_THUMB_DEF: u16 = 0x8;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

struct RawSection {
    name: String,
    segname: String,
    addr: u64,
    size: u64,
    offset: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    seg_perms: Perms,
}

impl RawSection {
    fn sect_type(&self) -> u32 {
        self.flags & 0xff
    }
    fn has_code(&self) -> bool {
        self.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
    }
}

/// Load a fat/universal binary, selecting one slice.
pub fn load_fat(path: PathBuf, data: Data, want: Option<&str>) -> Result<Binary> {
    let bytes = data.file();
    let is64 = read_u32_be(bytes, 0) == Some(0xcafe_babf);
    let count =
        read_u32_be(bytes, 4).ok_or_else(|| anyhow!("truncated fat Mach-O header"))? as usize;
    if count == 0 || count > 64 {
        bail!("fat Mach-O header claims {count} slices; the file is malformed");
    }
    let entsize = if is64 { 32 } else { 20 };
    let mut slices = Vec::with_capacity(count);
    for i in 0..count {
        let o = 8 + i * entsize;
        let (Some(cpu), Some(sub)) = (read_u32_be(bytes, o), read_u32_be(bytes, o + 4)) else {
            bail!("truncated fat Mach-O header (slice {i})");
        };
        let (offset, size) = if is64 {
            (
                read_u64(bytes, o + 8, false),
                read_u64(bytes, o + 16, false),
            )
        } else {
            (
                read_u32_be(bytes, o + 8).map(u64::from),
                read_u32_be(bytes, o + 12).map(u64::from),
            )
        };
        let (Some(offset), Some(size)) = (offset, size) else {
            bail!("truncated fat Mach-O header (slice {i})");
        };
        slices.push(FatSlice {
            arch: cpu_name(cpu, sub),
            offset,
            size,
        });
    }
    let selected = select_slice(&slices, want)?;
    let s = &slices[selected];
    let end = s
        .offset
        .checked_add(s.size)
        .filter(|&e| e <= bytes.len() as u64);
    let sub = end
        .and_then(|end| data.sub(s.offset as usize..end as usize))
        .ok_or_else(|| anyhow!("fat slice '{}' extends past the end of the file", s.arch))?;
    if detect(sub.slice()) != Detected::Macho {
        bail!(
            "fat slice '{}' is not a Mach-O image (perhaps a static library archive)",
            s.arch
        );
    }
    load(path, sub, Some(FatInfo { slices, selected }))
}

fn normalize_slice_name(s: &str) -> String {
    let s = s.trim().to_ascii_lowercase().replace('-', "_");
    match s.as_str() {
        "aarch64" => "arm64".into(),
        "amd64" | "x64" => "x86_64".into(),
        "x86" | "i686" | "i586" | "x86_32" => "i386".into(),
        "arm" => "armv7".into(),
        _ => s,
    }
}

fn select_slice(slices: &[FatSlice], want: Option<&str>) -> Result<usize> {
    let list = slices
        .iter()
        .map(|s| s.arch.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if let Some(w) = want {
        let w = normalize_slice_name(w);
        if let Some(i) = slices.iter().position(|s| s.arch == w) {
            return Ok(i);
        }
        if let Some(i) = slices.iter().position(|s| s.arch.starts_with(&w)) {
            return Ok(i);
        }
        bail!("no '{w}' slice in this fat binary (available: {list})");
    }
    let host: &[&str] = if cfg!(target_arch = "aarch64") {
        &["arm64", "arm64e"]
    } else if cfg!(target_arch = "x86_64") {
        &["x86_64", "x86_64h"]
    } else if cfg!(target_arch = "x86") {
        &["i386"]
    } else {
        &[]
    };
    for h in host {
        if let Some(i) = slices.iter().position(|s| s.arch == *h) {
            return Ok(i);
        }
    }
    bail!(
        "fat Mach-O with slices [{list}], none matching this machine; pick one with --slice <ARCH>"
    )
}

pub fn cpu_name(cputype: u32, subtype: u32) -> String {
    let sub = subtype & 0x00ff_ffff;
    match cputype {
        7 => "i386".into(),
        0x0100_0007 => if sub == 8 { "x86_64h" } else { "x86_64" }.into(),
        12 => match sub {
            5 => "armv4t",
            6 => "armv6",
            7 => "armv5",
            9 => "armv7",
            10 => "armv7f",
            11 => "armv7s",
            12 => "armv7k",
            13 => "armv8",
            14 => "armv6m",
            15 => "armv7m",
            16 => "armv7em",
            _ => "arm",
        }
        .into(),
        0x0100_000c => match sub {
            2 => "arm64e",
            _ => "arm64",
        }
        .into(),
        0x0200_000c => "arm64_32".into(),
        18 => "ppc".into(),
        0x0100_0012 => "ppc64".into(),
        _ => format!("cpu-{cputype:#x}"),
    }
}

fn macho_arch(cputype: u32) -> (Arch, u8) {
    match cputype {
        7 => (Arch::X86, 32),
        0x0100_0007 => (Arch::X86_64, 64),
        12 => (Arch::Arm, 32),
        0x0100_000c => (Arch::Arm64, 64),
        0x0200_000c => (Arch::Arm64, 32),
        18 => (Arch::PowerPc, 32),
        0x0100_0012 => (Arch::PowerPc64, 64),
        c => (Arch::Unknown(format!("macho-cpu-{c:#x}")), 64),
    }
}

/// Load a thin Mach-O image (`data.slice()`).
pub fn load(path: PathBuf, data: Data, fat: Option<FatInfo>) -> Result<Binary> {
    let mut warnings = Vec::new();
    let bytes = data.slice();
    let m = match MachO::parse(bytes, 0) {
        Ok(m) => m,
        Err(strict) => match MachO::parse_lossy(bytes, 0) {
            Ok(m) => {
                warnings.push(format!(
                    "malformed Mach-O ({strict}); parsed permissively, some data may be missing"
                ));
                m
            }
            Err(_) => return Err(anyhow!("invalid Mach-O file: {strict}")),
        },
    };
    let h = &m.header;
    let le = m.little_endian;
    let is64 = m.is_64;
    let ptr_size: u64 = if is64 { 8 } else { 4 };
    let (arch, bits) = macho_arch(h.cputype);
    let endian = if le { Endian::Little } else { Endian::Big };

    let mut info = MachoInfo {
        cputype: h.cputype,
        cpusubtype: h.cpusubtype,
        cpu_name: cpu_name(h.cputype, h.cpusubtype),
        filetype: h.filetype,
        flags: h.flags,
        ncmds: h.ncmds as u32,
        rpaths: m.rpaths.iter().map(|s| s.to_string()).collect(),
        fat,
        ..Default::default()
    };

    // ---- load commands: segments, sections, misc ---------------------------
    let mut segments = Vec::new();
    let mut regions = Vec::new();
    let mut raw_sections: Vec<RawSection> = Vec::new();
    let mut dysymtab = None;
    let mut interpreter = None;
    let mut main_entryoff = None;
    let mut export_trie = None;
    for lc in &m.load_commands {
        match &lc.command {
            CommandVariant::Segment64(c) => {
                let (seg, perms) = segment_from(
                    segments.len(),
                    &c.segname,
                    c.cmd,
                    c.vmaddr,
                    c.vmsize,
                    c.fileoff,
                    c.filesize,
                    c.initprot,
                    c.maxprot,
                );
                raw_sections.extend(read_sections(
                    bytes,
                    lc.offset + 72,
                    c.nsects,
                    true,
                    le,
                    perms,
                ));
                push_segment(&mut segments, &mut regions, seg);
            }
            CommandVariant::Segment32(c) => {
                let (seg, perms) = segment_from(
                    segments.len(),
                    &c.segname,
                    c.cmd,
                    u64::from(c.vmaddr),
                    u64::from(c.vmsize),
                    u64::from(c.fileoff),
                    u64::from(c.filesize),
                    c.initprot,
                    c.maxprot,
                );
                raw_sections.extend(read_sections(
                    bytes,
                    lc.offset + 56,
                    c.nsects,
                    false,
                    le,
                    perms,
                ));
                push_segment(&mut segments, &mut regions, seg);
            }
            CommandVariant::Dysymtab(d) => dysymtab = Some((d.indirectsymoff, d.nindirectsyms)),
            CommandVariant::CodeSignature(c) => {
                info.code_signature = Some(parse_code_signature(bytes, c.dataoff, c.datasize))
            }
            CommandVariant::EncryptionInfo32(e) => {
                info.encryption = Some(Encryption {
                    cryptid: e.cryptid,
                    offset: e.cryptoff,
                    size: e.cryptsize,
                })
            }
            CommandVariant::EncryptionInfo64(e) => {
                info.encryption = Some(Encryption {
                    cryptid: e.cryptid,
                    offset: e.cryptoff,
                    size: e.cryptsize,
                })
            }
            CommandVariant::Uuid(u) => info.uuid = Some(format_uuid(&u.uuid)),
            CommandVariant::BuildVersion(b) => {
                info.platform = Some(platform_name(b.platform).to_string());
                info.min_os = Some(version_string(b.minos));
                info.sdk = Some(version_string(b.sdk));
                for t in 0..b.ntools.min(32) as usize {
                    let o = lc.offset + 24 + t * 8;
                    if let (Some(tool), Some(ver)) =
                        (read_u32(bytes, o, le), read_u32(bytes, o + 4, le))
                    {
                        info.build_tools.push(format!(
                            "{} {}",
                            tool_name(tool),
                            version_string(ver)
                        ));
                    }
                }
            }
            CommandVariant::VersionMinMacosx(v) => {
                set_min_version(&mut info, "macOS", v.version, v.sdk)
            }
            CommandVariant::VersionMinIphoneos(v) => {
                set_min_version(&mut info, "iOS", v.version, v.sdk)
            }
            CommandVariant::VersionMinTvos(v) => {
                set_min_version(&mut info, "tvOS", v.version, v.sdk)
            }
            CommandVariant::VersionMinWatchos(v) => {
                set_min_version(&mut info, "watchOS", v.version, v.sdk)
            }
            CommandVariant::SourceVersion(s) => {
                let v = s.version;
                info.source_version = Some(format!(
                    "{}.{}.{}.{}.{}",
                    v >> 40,
                    (v >> 30) & 0x3ff,
                    (v >> 20) & 0x3ff,
                    (v >> 10) & 0x3ff,
                    v & 0x3ff
                ));
            }
            CommandVariant::LoadDylinker(d) => {
                interpreter = cstr_at(bytes, lc.offset + d.name as usize, 1024);
            }
            CommandVariant::Main(e) => {
                main_entryoff.get_or_insert(e.entryoff);
            }
            CommandVariant::DyldChainedFixups(_) => info.chained_fixups = true,
            CommandVariant::DyldInfo(d) | CommandVariant::DyldInfoOnly(d) => {
                info.dyld_info = true;
                if d.export_size > 0 {
                    export_trie = Some((d.export_off, d.export_size));
                }
            }
            CommandVariant::DyldExportsTrie(c) if c.datasize > 0 => {
                export_trie = Some((c.dataoff, c.datasize));
            }
            _ => {}
        }
    }

    let sections: Vec<Section> = raw_sections
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let zerofill = matches!(s.sect_type(), 0x1 | 0xc | 0x12);
            Section {
                index: i + 1,
                name: s.name.clone(),
                segment: Some(s.segname.clone()),
                addr: s.addr,
                size: s.size,
                offset: u64::from(s.offset),
                file_size: if zerofill || s.offset == 0 { 0 } else { s.size },
                perms: s.seg_perms,
                kind: section_type_name(s.sect_type()).to_string(),
                flags: u64::from(s.flags),
                alloc: true,
                tls: false,
            }
        })
        .collect();

    let image_base = if h.filetype == 1 {
        0
    } else {
        segments
            .iter()
            .find(|s| s.name == "__TEXT")
            .or_else(|| segments.iter().find(|s| s.offset == 0 && s.file_size > 0))
            .map_or(0, |s| s.vaddr)
    };

    // ---- symbols -----------------------------------------------------------
    let two_level = h.flags & MH_TWOLEVEL != 0;
    let lib_for = |n_desc: u16| -> Option<String> {
        if !two_level {
            return None;
        }
        match (n_desc >> 8) & 0xff {
            0 => None,
            0xfe => Some("<main executable>".into()),
            0xff => Some("<dynamic lookup>".into()),
            n => m.libs.get(n as usize).map(|s| s.to_string()),
        }
    };
    let mut symbols = Vec::new();
    // (symtab index, position in `symbols`, name, library, weak)
    let mut undefined: Vec<(usize, usize, String, Option<String>, bool)> = Vec::new();
    if let Some(syms) = &m.symbols {
        for (idx, entry) in syms.iter().enumerate() {
            let Ok((name, nl)) = entry else { continue };
            if nl.n_type & N_STAB != 0 {
                info.has_stabs = true;
                continue;
            }
            if name.is_empty() || name == "radr://5614542" {
                continue;
            }
            let t = nl.n_type & N_TYPE;
            let ext = nl.n_type & N_EXT != 0;
            let pext = nl.n_type & N_PEXT != 0;
            let common = t == N_UNDF && nl.n_value != 0;
            let defined = t != N_UNDF || common;
            let sect = (t == N_SECT && nl.n_sect > 0)
                .then(|| raw_sections.get(nl.n_sect - 1))
                .flatten();
            // Symbols such as __mh_execute_header reference a section but point
            // outside it (at the Mach header), so they are not code or data.
            let inside = sect.is_some_and(|s| nl.n_value >= s.addr && nl.n_value - s.addr < s.size);
            let kind = if common {
                SymKind::Common
            } else if let Some(s) = sect.filter(|_| inside) {
                if s.has_code() {
                    SymKind::Func
                } else {
                    SymKind::Object
                }
            } else {
                SymKind::NoType
            };
            let weak = nl.n_desc & (N_WEAK_REF | N_WEAK_DEF) != 0;
            let bind = match (ext && !pext, weak) {
                (true, true) => SymBind::Weak,
                (true, false) => SymBind::Global,
                _ => SymBind::Local,
            };
            let library = (!defined).then(|| lib_for(nl.n_desc)).flatten();
            if !defined && ext {
                undefined.push((idx, symbols.len(), name.to_string(), library.clone(), weak));
            }
            symbols.push(Symbol {
                name: name.to_string(),
                demangled: demangle(name),
                addr: if defined { nl.n_value } else { 0 },
                size: if common { nl.n_value } else { 0 },
                kind,
                bind,
                section: match t {
                    N_SECT => sect.map(|s| format!("{},{}", s.segname, s.name)),
                    N_ABS => Some("ABS".into()),
                    _ if common => Some("COMMON".into()),
                    _ => None,
                },
                defined,
                dynamic: ext && !pext,
                version: None,
                library,
                thumb: nl.n_desc & N_ARM_THUMB_DEF != 0,
            });
        }
    }
    let sec_ranges: HashMap<String, (u64, u64)> = raw_sections
        .iter()
        .map(|s| {
            (
                format!("{},{}", s.segname, s.name),
                (s.addr, s.addr.saturating_add(s.size)),
            )
        })
        .collect();
    super::estimate_sizes(&mut symbols, |name| sec_ranges.get(name).copied());

    // ---- imports (undefined symbols + indirect symbol table) ---------------------
    let mut stubs: HashMap<u32, u64> = HashMap::new();
    let mut slots: HashMap<u32, u64> = HashMap::new();
    if let Some((off, count)) = dysymtab {
        let indirect: Vec<u32> = (0..count.min(1 << 22) as usize)
            .map_while(|i| read_u32(bytes, off as usize + i * 4, le))
            .collect();
        for s in &raw_sections {
            let (entry, is_stub) = match s.sect_type() {
                0x8 => (u64::from(s.reserved2), true),
                0x6 | 0x7 | 0x10 | 0x14 => (ptr_size, false),
                _ => continue,
            };
            if entry == 0 {
                continue;
            }
            for j in 0..(s.size / entry).min(1 << 20) {
                let Some(&sym) = indirect.get(s.reserved1 as usize + j as usize) else {
                    break;
                };
                if sym & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
                    continue;
                }
                let addr = s.addr.wrapping_add(j * entry);
                let map = if is_stub { &mut stubs } else { &mut slots };
                map.entry(sym).or_insert(addr);
            }
        }
    }
    let mut imports: Vec<Import> = Vec::with_capacity(undefined.len());
    for (idx, pos, name, library, weak) in undefined {
        let plt = stubs.get(&(idx as u32)).copied();
        if plt.is_some() {
            // Called through a __stubs entry, so it is a function.
            symbols[pos].kind = SymKind::Func;
        }
        imports.push(Import {
            demangled: demangle(&name),
            name: Some(name),
            ordinal: None,
            library,
            version: None,
            slot: slots.get(&(idx as u32)).copied(),
            plt,
            weak,
            delayed: false,
        });
    }
    if imports.is_empty()
        && let Some(Ok(list)) = super::optional(|| m.imports())
    {
        imports = list
            .into_iter()
            .map(|i| Import {
                demangled: demangle(i.name),
                name: Some(i.name.to_string()),
                ordinal: None,
                library: Some(i.dylib.to_string()),
                version: None,
                slot: Some(i.address),
                plt: None,
                weak: i.is_weak,
                delayed: false,
            })
            .collect();
    }

    // ---- exports -------------------------------------------------------------
    let code_at = |va: u64| {
        raw_sections
            .iter()
            .any(|s| s.has_code() && va >= s.addr && va - s.addr < s.size)
    };
    let mut exports = Vec::new();
    if let Some((off, size)) = export_trie {
        let (list, truncated) = walk_export_trie(bytes, off as usize, size as usize, &m.libs);
        if truncated {
            warnings.push(
                "export trie is malformed (cycles or bad offsets); exports may be incomplete"
                    .into(),
            );
        }
        for e in list {
            let (addr, forwarder) = match e.target {
                TrieTarget::Address(a) if e.absolute => (a, None),
                TrieTarget::Address(a) => (image_base.wrapping_add(a), None),
                TrieTarget::Reexport { lib, name } => {
                    let target = name.unwrap_or_else(|| e.name.clone());
                    (0, Some(format!("{lib}:{target}")))
                }
            };
            exports.push(Export {
                demangled: demangle(&e.name),
                kind: if forwarder.is_none() && code_at(addr) {
                    SymKind::Func
                } else {
                    SymKind::Object
                },
                name: Some(e.name),
                addr,
                ordinal: None,
                forwarder,
            });
        }
    }
    if exports.is_empty() {
        exports = symbols
            .iter()
            .filter(|s| s.defined && s.dynamic && s.section.as_deref() != Some("ABS"))
            .map(|s| Export {
                name: Some(s.name.clone()),
                demangled: s.demangled.clone(),
                addr: s.addr,
                ordinal: None,
                forwarder: None,
                kind: s.kind,
            })
            .collect();
    }

    // ---- classification --------------------------------------------------------
    let kind = match h.filetype {
        1 => FileKind::Object,
        2 | 5 => FileKind::Executable,
        3 | 6 | 7 | 8 | 9 => FileKind::SharedLibrary,
        4 => FileKind::Core,
        11 => FileKind::Driver,
        _ => FileKind::Other,
    };
    let os = info.platform.clone().unwrap_or_else(|| "Darwin".into());
    let abi = match (&info.min_os, &info.sdk) {
        (Some(min), Some(sdk)) => Some(format!("min {min}, SDK {sdk}")),
        (Some(min), None) => Some(format!("min {min}")),
        _ => None,
    };
    // LC_MAIN holds a file offset: map it through the segments ourselves rather
    // than trusting goblin's unchecked `vmaddr - fileoff`.
    let entry = match main_entryoff {
        Some(off) => {
            let va = regions
                .iter()
                .find(|r| r.file_size > 0 && off >= r.offset && off - r.offset < r.file_size)
                .map(|r| r.va.wrapping_add(off - r.offset));
            if va.is_none() {
                warnings.push(format!(
                    "LC_MAIN entry offset {off:#x} is outside every segment"
                ));
            }
            va
        }
        None => (m.entry != 0).then_some(m.entry),
    };
    let thumb = arch == Arch::Arm && entry.is_some_and(|e| e & 1 == 1);
    let libraries = m.libs.iter().skip(1).map(|s| s.to_string()).collect();
    let file_size = data.file().len() as u64;
    drop(m);

    Ok(Binary {
        path,
        format: Format::Macho,
        kind,
        arch,
        bits,
        endian,
        thumb,
        os,
        abi,
        entry: entry.map(|e| if thumb { e & !1 } else { e }),
        image_base,
        file_size,
        sections,
        segments,
        regions,
        symbols,
        imports,
        exports,
        relocations: Vec::new(),
        libraries,
        interpreter,
        details: Details::Macho(info),
        warnings,
        data,
    })
}

struct TrieExport {
    name: String,
    absolute: bool,
    target: TrieTarget,
}

enum TrieTarget {
    /// Offset from the image base (or an absolute value, see `absolute`).
    Address(u64),
    Reexport {
        lib: String,
        name: Option<String>,
    },
}

fn uleb(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    for shift in (0..64).step_by(7) {
        let b = *data.get(*pos)?;
        *pos += 1;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// Walk the dyld export trie iteratively with a visited set. goblin's walker
/// recurses without cycle detection, so a crafted trie can overflow the stack.
/// Returns the exports and whether the trie had to be cut short.
fn walk_export_trie(
    bytes: &[u8],
    off: usize,
    size: usize,
    libs: &[&str],
) -> (Vec<TrieExport>, bool) {
    const REEXPORT: u64 = 0x08;
    const STUB_AND_RESOLVER: u64 = 0x10;
    const KIND_ABSOLUTE: u64 = 0x02;
    const MAX_EXPORTS: usize = 2_000_000;
    let Some(trie) = off.checked_add(size).and_then(|end| bytes.get(off..end)) else {
        return (Vec::new(), true);
    };
    let mut out = Vec::new();
    let mut truncated = false;
    let mut visited = std::collections::HashSet::new();
    let mut stack: Vec<(usize, String)> = vec![(0, String::new())];
    while let Some((node, prefix)) = stack.pop() {
        if !visited.insert(node) || out.len() >= MAX_EXPORTS {
            truncated = true;
            continue;
        }
        let mut p = node;
        let Some(terminal_size) = uleb(trie, &mut p) else {
            truncated = true;
            continue;
        };
        let Some(children) = usize::try_from(terminal_size)
            .ok()
            .and_then(|t| p.checked_add(t))
        else {
            truncated = true;
            continue;
        };
        if terminal_size > 0 {
            let mut q = p;
            let flags = uleb(trie, &mut q).unwrap_or(0);
            let target = if flags & REEXPORT != 0 {
                let ordinal = uleb(trie, &mut q).unwrap_or(0);
                let lib = libs
                    .get(ordinal as usize)
                    .copied()
                    .unwrap_or("?")
                    .to_string();
                let name = cstr_at(trie, q, 4096).filter(|n| !n.is_empty());
                TrieTarget::Reexport { lib, name }
            } else {
                let addr = uleb(trie, &mut q).unwrap_or(0);
                if flags & STUB_AND_RESOLVER != 0 {
                    let _resolver = uleb(trie, &mut q);
                }
                TrieTarget::Address(addr)
            };
            out.push(TrieExport {
                name: prefix.clone(),
                absolute: flags & 0x3 == KIND_ABSOLUTE,
                target,
            });
        }
        // Child count is a single byte in the dyld format.
        let Some(&count) = trie.get(children) else {
            continue;
        };
        let mut c = children + 1;
        for _ in 0..count {
            let Some(edge) = cstr_at(trie, c, 4096) else {
                truncated = true;
                break;
            };
            c += edge.len() + 1;
            let Some(child) = uleb(trie, &mut c).and_then(|v| usize::try_from(v).ok()) else {
                truncated = true;
                break;
            };
            if child >= trie.len() || prefix.len() + edge.len() > 8192 {
                truncated = true;
                continue;
            }
            stack.push((child, format!("{prefix}{edge}")));
        }
    }
    (out, truncated)
}

/// Parse the embedded signature SuperBlob far enough to tell ad-hoc from
/// certificate signatures and read the identifier / team ID / flags.
fn parse_code_signature(bytes: &[u8], offset: u32, size: u32) -> CodeSignature {
    const SUPERBLOB: u32 = 0xfade_0cc0;
    const CODEDIRECTORY: u32 = 0xfade_0c02;
    const CMS_WRAPPER: u32 = 0xfade_0b01;
    let mut cs = CodeSignature {
        offset,
        size,
        flags: None,
        identifier: None,
        team_id: None,
        has_cms: false,
    };
    let base = offset as usize;
    let be = |o: usize| read_u32(bytes, o, false);
    if be(base) != Some(SUPERBLOB) {
        return cs;
    }
    let count = be(base + 8).unwrap_or(0).min(64) as usize;
    for i in 0..count {
        let (Some(slot), Some(blob_off)) = (be(base + 12 + i * 8), be(base + 16 + i * 8)) else {
            break;
        };
        let blob = base + blob_off as usize;
        match be(blob) {
            Some(CODEDIRECTORY) if slot == 0 => {
                let version = be(blob + 8).unwrap_or(0);
                cs.flags = be(blob + 12);
                if let Some(ident) = be(blob + 20) {
                    cs.identifier =
                        cstr_at(bytes, blob + ident as usize, 512).filter(|s| !s.is_empty());
                }
                if version >= 0x20200
                    && let Some(team) = be(blob + 48).filter(|&t| t != 0)
                {
                    cs.team_id =
                        cstr_at(bytes, blob + team as usize, 128).filter(|s| !s.is_empty());
                }
            }
            Some(CMS_WRAPPER) => cs.has_cms = be(blob + 4).is_some_and(|len| len > 8),
            _ => {}
        }
    }
    cs
}

fn prot(p: u32) -> Perms {
    Perms::new(p & 1 != 0, p & 2 != 0, p & 4 != 0)
}

#[allow(clippy::too_many_arguments)]
fn segment_from(
    index: usize,
    segname: &[u8; 16],
    cmd: u32,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    initprot: u32,
    maxprot: u32,
) -> (Segment, Perms) {
    let perms = prot(initprot);
    let seg = Segment {
        index,
        name: fixed_name(segname),
        kind: cmd,
        vaddr: vmaddr,
        vsize: vmsize,
        offset: fileoff,
        file_size: filesize,
        perms,
        max_perms: Some(prot(maxprot)),
        align: 0,
        loadable: true,
    };
    (seg, perms)
}

fn push_segment(segments: &mut Vec<Segment>, regions: &mut Vec<Region>, seg: Segment) {
    if seg.vsize > 0 {
        regions.push(Region {
            name: seg.name.clone(),
            va: seg.vaddr,
            vsize: seg.vsize,
            offset: seg.offset,
            file_size: seg.file_size.min(seg.vsize),
            perms: seg.perms,
        });
    }
    segments.push(seg);
}

fn read_sections(
    bytes: &[u8],
    start: usize,
    nsects: u32,
    is64: bool,
    le: bool,
    seg_perms: Perms,
) -> Vec<RawSection> {
    let size = if is64 { 80 } else { 68 };
    let mut out = Vec::new();
    for i in 0..nsects.min(4096) as usize {
        let o = start + i * size;
        let Some(raw) = bytes.get(o..o + size) else {
            break;
        };
        let u32_at = |off: usize| read_u32(raw, off, le).unwrap_or(0);
        let (addr, sz, rest) = if is64 {
            (
                read_u64(raw, 32, le).unwrap_or(0),
                read_u64(raw, 40, le).unwrap_or(0),
                48,
            )
        } else {
            (u64::from(u32_at(32)), u64::from(u32_at(36)), 40)
        };
        out.push(RawSection {
            name: fixed_name(&raw[0..16]),
            segname: fixed_name(&raw[16..32]),
            addr,
            size: sz,
            offset: u32_at(rest),
            flags: u32_at(rest + 16),
            reserved1: u32_at(rest + 20),
            reserved2: u32_at(rest + 24),
            seg_perms,
        });
    }
    out
}

fn set_min_version(info: &mut MachoInfo, platform: &str, version: u32, sdk: u32) {
    if info.platform.is_none() {
        info.platform = Some(platform.to_string());
        info.min_os = Some(version_string(version));
        info.sdk = Some(version_string(sdk));
    }
}

/// `xxxx.yy.zz` nibble-packed version.
fn version_string(v: u32) -> String {
    let (a, b, c) = (v >> 16, (v >> 8) & 0xff, v & 0xff);
    if c == 0 {
        format!("{a}.{b}")
    } else {
        format!("{a}.{b}.{c}")
    }
}

fn format_uuid(u: &[u8; 16]) -> String {
    let h = super::hex_string(u).to_ascii_uppercase();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn platform_name(p: u32) -> &'static str {
    match p {
        1 => "macOS",
        2 => "iOS",
        3 => "tvOS",
        4 => "watchOS",
        5 => "bridgeOS",
        6 => "Mac Catalyst",
        7 => "iOS Simulator",
        8 => "tvOS Simulator",
        9 => "watchOS Simulator",
        10 => "DriverKit",
        11 => "visionOS",
        12 => "visionOS Simulator",
        _ => "unknown platform",
    }
}

fn tool_name(t: u32) -> &'static str {
    match t {
        1 => "clang",
        2 => "swift",
        3 => "ld",
        4 => "lld",
        1024 => "metal",
        _ => "tool",
    }
}

fn section_type_name(t: u32) -> &'static str {
    match t {
        0x0 => "regular",
        0x1 => "zerofill",
        0x2 => "cstring_literals",
        0x3 => "4byte_literals",
        0x4 => "8byte_literals",
        0x5 => "literal_pointers",
        0x6 => "non_lazy_symbol_pointers",
        0x7 => "lazy_symbol_pointers",
        0x8 => "symbol_stubs",
        0x9 => "mod_init_func_pointers",
        0xa => "mod_term_func_pointers",
        0xb => "coalesced",
        0xc => "gb_zerofill",
        0xd => "interposing",
        0xe => "16byte_literals",
        0xf => "dtrace_dof",
        0x10 => "lazy_dylib_symbol_pointers",
        0x11 => "thread_local_regular",
        0x12 => "thread_local_zerofill",
        0x13 => "thread_local_variables",
        0x14 => "thread_local_variable_pointers",
        0x15 => "thread_local_init_function_pointers",
        0x16 => "init_func_offsets",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slices(names: &[&str]) -> Vec<FatSlice> {
        names
            .iter()
            .map(|n| FatSlice {
                arch: n.to_string(),
                offset: 0,
                size: 0,
            })
            .collect()
    }

    #[test]
    fn slice_selection() {
        let s = slices(&["x86_64", "arm64"]);
        assert_eq!(select_slice(&s, Some("arm64")).unwrap(), 1);
        assert_eq!(select_slice(&s, Some("aarch64")).unwrap(), 1);
        assert_eq!(select_slice(&s, Some("x86-64")).unwrap(), 0);
        assert!(select_slice(&s, Some("ppc")).is_err());
        let s = slices(&["armv7", "arm64e"]);
        assert_eq!(select_slice(&s, Some("arm64")).unwrap(), 1);
    }

    #[test]
    fn versions_and_names() {
        assert_eq!(version_string(0x000b_0000), "11.0");
        assert_eq!(version_string(0x000a_0f06), "10.15.6");
        assert_eq!(cpu_name(0x0100_000c, 2), "arm64e");
        assert_eq!(cpu_name(0x0100_0007, 3), "x86_64");
    }
}
