//! PE/COFF loader (goblin) -> unified model.
//!
//! VA, RVA and file offsets are kept strictly apart: the model stores VAs
//! (`image_base + rva`), and every RVA -> offset translation goes through the
//! section/header regions built here.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use goblin::pe::{
    PE, export::ExportAddressTableEntry, import::SyntheticImportLookupTableEntry,
    options::ParseOptions,
};

use super::{cstr_at, demangle, fixed_name, read_u16, read_u32, read_u64};
use crate::model::*;

const IMAGE_FILE_DLL: u16 = 0x2000;

const SCN_CNT_CODE: u32 = 0x0000_0020;
const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

const DIR_NAMES: [&str; 16] = [
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "SECURITY",
    "BASERELOC",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBALPTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "CLR_RUNTIME",
    "RESERVED",
];

pub fn load(path: PathBuf, data: Data) -> Result<Binary> {
    let mut warnings = Vec::new();
    let bytes = data.slice();
    let file_len = bytes.len() as u64;

    let mut opts = ParseOptions::default().with_parse_resources(false);
    opts.parse_attribute_certificates = true;
    let pe = match PE::parse_with_opts(bytes, &opts) {
        Ok(pe) => pe,
        Err(strict) => {
            let lax = opts.with_parse_mode(goblin::options::ParseMode::Permissive);
            match PE::parse_with_opts(bytes, &lax) {
                Ok(pe) => {
                    warnings.push(format!(
                        "malformed PE ({strict}); parsed permissively, some data may be missing"
                    ));
                    pe
                }
                Err(_) => match PE::parse_with_opts(bytes, &lax.with_parse_imports(false)) {
                    Ok(pe) => {
                        warnings.push(format!(
                            "malformed PE ({strict}); import table could not be parsed"
                        ));
                        pe
                    }
                    Err(_) => return Err(anyhow!("invalid PE file: {strict}")),
                },
            }
        }
    };

    let coff = &pe.header.coff_header;
    let machine = coff.machine;
    let image_base = pe.image_base;
    let is64 = pe.is_64;
    let ptr_size: u64 = if is64 { 8 } else { 4 };
    let (arch, thumb) = pe_arch(machine);
    let bits = match arch {
        Arch::Arm64 | Arch::X86_64 | Arch::RiscV64 | Arch::LoongArch64 => 64,
        _ if is64 => 64,
        _ => 32,
    };

    let mut info = PeInfo {
        pe32_plus: is64,
        machine,
        characteristics: coff.characteristics,
        timestamp: coff.time_date_stamp,
        has_coff_symbols: coff.pointer_to_symbol_table != 0 && coff.number_of_symbol_table != 0,
        ..Default::default()
    };
    let mut file_alignment = 0x200;
    let mut size_of_headers = 0x400u64;
    let mut dirs: Vec<(usize, u32, u32)> = Vec::new();
    if let Some(oh) = &pe.header.optional_header {
        let sf = &oh.standard_fields;
        let wf = &oh.windows_fields;
        info.linker_version = (sf.major_linker_version, sf.minor_linker_version);
        info.os_version = (
            wf.major_operating_system_version,
            wf.minor_operating_system_version,
        );
        info.subsystem_version = (wf.major_subsystem_version, wf.minor_subsystem_version);
        info.subsystem = wf.subsystem;
        info.dll_characteristics = wf.dll_characteristics;
        info.checksum = wf.check_sum;
        info.size_of_image = wf.size_of_image;
        info.size_of_headers = wf.size_of_headers;
        info.section_alignment = wf.section_alignment;
        info.file_alignment = wf.file_alignment;
        file_alignment = wf.file_alignment;
        size_of_headers = u64::from(wf.size_of_headers);
        // Not `DataDirectories::dirs()`: it panics when the reserved 16th entry is
        // non-zero, which malformed (and some malicious) images do.
        for (idx, entry) in oh.data_directories.data_directories.iter().enumerate() {
            let Some((_, dd)) = entry else { continue };
            dirs.push((idx, dd.virtual_address, dd.size));
            if dd.virtual_address != 0 || dd.size != 0 {
                info.data_directories.push(DataDir {
                    index: idx,
                    name: DIR_NAMES.get(idx).copied().unwrap_or("?"),
                    rva: dd.virtual_address,
                    size: dd.size,
                });
            }
        }
    } else {
        warnings.push("no optional header (COFF object or damaged image)".into());
    }
    let dir = |idx: usize| dirs.iter().find(|d| d.0 == idx).map(|d| (d.1, d.2));

    // ---- sections & regions -------------------------------------------
    let mut sections = Vec::with_capacity(pe.sections.len());
    let mut regions = vec![Region {
        name: "headers".into(),
        va: image_base,
        vsize: size_of_headers.max(1),
        offset: 0,
        file_size: size_of_headers.min(file_len),
        perms: Perms::new(true, false, false),
    }];
    for (i, s) in pe.sections.iter().enumerate() {
        let c = s.characteristics;
        let name = s.real_name.clone().unwrap_or_else(|| fixed_name(&s.name));
        let vsize = if s.virtual_size == 0 {
            s.size_of_raw_data
        } else {
            s.virtual_size
        };
        let raw_off = if file_alignment >= 0x200 {
            u64::from(s.pointer_to_raw_data & !0x1ff)
        } else {
            u64::from(s.pointer_to_raw_data)
        };
        let raw_size = if s.pointer_to_raw_data == 0 {
            0
        } else {
            u64::from(s.size_of_raw_data)
        };
        let va = image_base.wrapping_add(u64::from(s.virtual_address));
        let perms = Perms::new(
            c & SCN_MEM_READ != 0,
            c & SCN_MEM_WRITE != 0,
            c & SCN_MEM_EXECUTE != 0,
        );
        let mut kinds = Vec::new();
        if c & SCN_CNT_CODE != 0 {
            kinds.push("code");
        }
        if c & SCN_CNT_INITIALIZED_DATA != 0 {
            kinds.push("data");
        }
        if c & SCN_CNT_UNINITIALIZED_DATA != 0 {
            kinds.push("bss");
        }
        sections.push(Section {
            index: i + 1,
            name: name.clone(),
            segment: None,
            addr: va,
            size: u64::from(vsize),
            offset: raw_off,
            file_size: raw_size,
            perms,
            kind: if kinds.is_empty() {
                "-".into()
            } else {
                kinds.join("+")
            },
            flags: u64::from(c),
            alloc: true,
            tls: false,
        });
        if vsize > 0 {
            regions.push(Region {
                name,
                va,
                vsize: u64::from(vsize),
                offset: raw_off,
                file_size: raw_size.min(u64::from(vsize)),
                perms,
            });
        }
    }
    let rva_off = |rva: u64| -> Option<usize> {
        let va = image_base.checked_add(rva)?;
        regions
            .iter()
            .find(|r| r.contains_va(va) && va - r.va < r.file_size)
            .map(|r| (r.offset + (va - r.va)) as usize)
            .filter(|&o| o < bytes.len())
    };
    let exec_at = |va: u64| -> bool { sections.iter().any(|s| s.contains_va(va) && s.perms.x) };

    // ---- imports --------------------------------------------------------
    let mut imports = Vec::new();
    let mut libraries: Vec<String> = Vec::new();
    let mut seen_libs: HashSet<String> = HashSet::new();
    if let Some(id) = &pe.import_data {
        for d in &id.import_data {
            let lib = d.name.to_string();
            if seen_libs.insert(lib.to_ascii_lowercase()) {
                libraries.push(lib.clone());
            }
            let e = &d.import_directory_entry;
            let base_rva = if e.import_address_table_rva != 0 {
                e.import_address_table_rva
            } else {
                e.import_lookup_table_rva
            };
            let Some(entries) = &d.import_lookup_table else {
                continue;
            };
            for (i, entry) in entries.iter().enumerate() {
                let slot = image_base.wrapping_add(u64::from(base_rva) + i as u64 * ptr_size);
                let (name, ordinal) = match entry {
                    SyntheticImportLookupTableEntry::OrdinalNumber(o) => {
                        (None, Some(u32::from(*o)))
                    }
                    SyntheticImportLookupTableEntry::HintNameTableRVA((_, h)) => {
                        (Some(h.name.to_string()), None)
                    }
                };
                imports.push(Import {
                    demangled: name.as_deref().and_then(demangle),
                    name,
                    ordinal,
                    library: Some(lib.clone()),
                    version: None,
                    slot: Some(slot),
                    plt: None,
                    weak: false,
                    delayed: false,
                });
            }
        }
    }
    if let Some((rva, size)) = dir(13).filter(|d| d.0 != 0 && d.1 != 0) {
        let delayed = parse_delay_imports(bytes, u64::from(rva), image_base, is64, &rva_off);
        for imp in &delayed {
            if let Some(lib) = &imp.library
                && seen_libs.insert(lib.to_ascii_lowercase())
            {
                libraries.push(lib.clone());
            }
        }
        if delayed.is_empty() && size > 0 {
            warnings.push("delay-load import directory present but unreadable".into());
        }
        imports.extend(delayed);
    }

    // ---- exports --------------------------------------------------------
    let mut exports = Vec::new();
    if let Some(ed) = &pe.export_data {
        let base = ed.export_directory_table.ordinal_base;
        let mut names: HashMap<usize, Vec<String>> = HashMap::new();
        for (i, &name_rva) in ed.export_name_pointer_table.iter().enumerate() {
            let Some(&ord_idx) = ed.export_ordinal_table.get(i) else {
                break;
            };
            let name = rva_off(u64::from(name_rva))
                .and_then(|o| cstr_at(bytes, o, 1024))
                .unwrap_or_default();
            names.entry(ord_idx as usize).or_default().push(name);
        }
        for (i, entry) in ed.export_address_table.iter().enumerate() {
            let (rva, forwarder) = match *entry {
                ExportAddressTableEntry::ExportRVA(r) => (r, None),
                ExportAddressTableEntry::ForwarderRVA(r) => (
                    r,
                    rva_off(u64::from(r)).and_then(|o| cstr_at(bytes, o, 1024)),
                ),
            };
            if rva == 0 {
                continue;
            }
            let ordinal = base.wrapping_add(i as u32);
            let addr = if forwarder.is_some() {
                0
            } else {
                image_base.wrapping_add(u64::from(rva))
            };
            let kind = if forwarder.is_none() && exec_at(addr) {
                SymKind::Func
            } else {
                SymKind::Object
            };
            let mk = |name: Option<String>| Export {
                demangled: name.as_deref().and_then(demangle),
                name,
                addr,
                ordinal: Some(ordinal),
                forwarder: forwarder.clone(),
                kind,
            };
            match names.get(&i) {
                Some(list) => exports.extend(list.iter().map(|n| mk(Some(n.clone())))),
                None => exports.push(mk(None)),
            }
        }
    }

    // ---- symbols (COFF symbol table, then exports) ------------------------
    let mut symbols = Vec::new();
    if info.has_coff_symbols {
        if let Ok(Some(symtab)) = coff.symbols(bytes) {
            let strtab = coff.strings(bytes).ok().flatten();
            for (idx, inline, s) in symtab.iter() {
                let sc = s.storage_class;
                // FUNCTION (.bf/.ef), CLR token, section definitions: not useful here.
                if matches!(sc, 101 | 107) || s.is_section_definition() {
                    continue;
                }
                if sc == 103 {
                    let fname = symtab
                        .aux_file(idx + 1, s.number_of_aux_symbols as usize)
                        .map(str::to_string)
                        .unwrap_or_default();
                    if !fname.is_empty() {
                        symbols.push(Symbol {
                            name: fname,
                            demangled: None,
                            addr: 0,
                            size: 0,
                            kind: SymKind::File,
                            bind: SymBind::Local,
                            section: Some("ABS".into()),
                            defined: true,
                            dynamic: false,
                            version: None,
                            library: None,
                            thumb: false,
                        });
                    }
                    continue;
                }
                let name = match inline {
                    Some(n) => n.to_string(),
                    None => match &strtab {
                        Some(st) => s.name(st).unwrap_or("").to_string(),
                        None => continue,
                    },
                };
                // Section symbols (`.text`, `.idata$5`, ...): MinGW import-library
                // objects emit them without aux records, so check the name too.
                if name.is_empty() || (matches!(sc, 3 | 104) && name.starts_with('.')) {
                    continue;
                }
                let (defined, section, addr) = match s.section_number {
                    n if n > 0 => {
                        let Some(sec) = sections.get(n as usize - 1) else {
                            continue;
                        };
                        (
                            true,
                            Some(sec.name.clone()),
                            sec.addr.wrapping_add(u64::from(s.value)),
                        )
                    }
                    0 => (s.value != 0, None, 0),
                    -1 => (true, Some("ABS".to_string()), u64::from(s.value)),
                    _ => continue,
                };
                let is_func = (s.typ >> 4) & 0x3 == 2;
                let kind = if is_func {
                    SymKind::Func
                } else if section.as_deref() == Some("ABS") || !defined || exec_at(addr) {
                    // Absolute values, undefined externals and non-function labels in code.
                    SymKind::NoType
                } else {
                    SymKind::Object
                };
                let bind = match sc {
                    2 => SymBind::Global,
                    105 => SymBind::Weak,
                    3 | 6 => SymBind::Local,
                    _ => SymBind::Unknown,
                };
                symbols.push(Symbol {
                    demangled: demangle(&name),
                    name,
                    addr,
                    size: 0,
                    kind,
                    bind,
                    section,
                    defined,
                    dynamic: false,
                    version: None,
                    library: None,
                    thumb: false,
                });
            }
        } else {
            warnings.push("COFF symbol table pointer is invalid".into());
        }
    }
    let known: HashSet<(String, u64)> = symbols.iter().map(|s| (s.name.clone(), s.addr)).collect();
    for e in &exports {
        let (Some(name), None) = (&e.name, &e.forwarder) else {
            continue;
        };
        if known.contains(&(name.clone(), e.addr)) {
            continue;
        }
        symbols.push(Symbol {
            name: name.clone(),
            demangled: e.demangled.clone(),
            addr: e.addr,
            size: 0,
            kind: e.kind,
            bind: SymBind::Global,
            section: sections
                .iter()
                .find(|s| s.contains_va(e.addr))
                .map(|s| s.name.clone()),
            defined: true,
            dynamic: true,
            version: None,
            library: None,
            thumb: false,
        });
    }
    let sec_ranges: HashMap<String, (u64, u64)> = sections
        .iter()
        .map(|s| (s.name.clone(), (s.addr, s.addr.saturating_add(s.size))))
        .collect();
    super::estimate_sizes(&mut symbols, |name| sec_ranges.get(name).copied());

    // ---- base relocations ----------------------------------------------
    let mut relocations = Vec::new();
    if let Some(rd) = &pe.relocation_data {
        for block in rd.blocks().flatten() {
            for word in block.words().flatten() {
                let t = word.reloc_type();
                if t == 0 {
                    continue; // IMAGE_REL_BASED_ABSOLUTE: padding
                }
                relocations.push(Relocation {
                    addr: image_base.wrapping_add(u64::from(block.rva) + u64::from(word.offset())),
                    kind: base_reloc_name(t, machine).to_string(),
                    raw_type: u32::from(t),
                    symbol: None,
                    addend: None,
                    source: ".reloc".into(),
                });
            }
        }
    }

    // ---- assorted directories ---------------------------------------------
    // Parsed by hand: goblin drops every field after SecurityCookie for some
    // valid 32-bit layouts (e.g. Size 0xc0 from VS2026), breaking SafeSEH/CFG.
    if let Some((rva, _)) = dir(10).filter(|d| d.0 != 0) {
        info.load_config = parse_load_config(bytes, u64::from(rva), is64, &rva_off);
    }
    if let Some((off, size)) = dir(4).filter(|d| d.0 != 0 && d.1 != 0) {
        info.signature = Some(Signature {
            offset: off,
            size,
            certificates: pe.certificates.len(),
        });
    }
    if let Some(dd) = &pe.debug_data {
        if let Some(cv) = &dd.codeview_pdb70_debug_info {
            info.pdb = Some(PdbInfo {
                path: fixed_name(cv.filename),
                guid: format_guid(&cv.signature),
                age: cv.age,
            });
        } else if let Some(cv) = &dd.codeview_pdb20_debug_info {
            info.pdb = Some(PdbInfo {
                path: fixed_name(cv.filename),
                guid: format!("{:08X}", cv.signature),
                age: cv.age,
            });
        }
        info.reproducible = dd.repro_info.is_some();
        info.ex_dll_characteristics = dd
            .ex_dll_characteristics_info
            .as_ref()
            .map(|x| x.characteristics_ex);
        info.gs_functions = dd.vcfeature_info.as_ref().map(|v| v.guard_stack_count);
    }
    if let Some(rich) = &pe.header.rich_header {
        info.has_rich_header = true;
        info.rich = rich
            .metadatas()
            .flatten()
            .map(|m| RichEntry {
                product: m.product,
                build: m.build,
                count: m.use_count,
            })
            .collect();
    }
    if let Some(clr) = &pe.clr_data {
        let h = &clr.cor20_header;
        info.clr = Some(ClrInfo {
            runtime_version: format!("{}.{}", h.major_runtime_version, h.minor_runtime_version),
            metadata_version: Some(
                clr.metadata_header
                    .version
                    .trim_end_matches('\0')
                    .to_string(),
            )
            .filter(|s| !s.is_empty()),
            flags: h.flags,
            il_only: h.is_il_only(),
            requires_32bit: h.is_32bit_required(),
            strong_name_signed: h.is_strong_name_signed(),
        });
    } else if dir(14).is_some_and(|d| d.0 != 0) {
        // CLR header present but goblin could not parse it: still a .NET image.
        info.clr = Some(ClrInfo {
            runtime_version: "?".into(),
            metadata_version: None,
            flags: 0,
            il_only: false,
            requires_32bit: false,
            strong_name_signed: false,
        });
    }
    if let Some(tls) = &pe.tls_data {
        info.tls_callbacks = tls.callbacks.clone();
    }

    // Overlay: data past the last section that is neither the Authenticode blob
    // nor the COFF symbol/string table (MinGW keeps that after the sections).
    let mut data_end = sections
        .iter()
        .filter(|s| s.file_size > 0)
        .map(|s| s.offset + s.file_size)
        .max()
        .unwrap_or(size_of_headers)
        .max(size_of_headers);
    if info.has_coff_symbols {
        let sym_start = u64::from(coff.pointer_to_symbol_table);
        let str_start = sym_start + u64::from(coff.number_of_symbol_table) * 18;
        let str_size = super::read_u32_le(bytes, str_start as usize).map_or(0, u64::from);
        if sym_start >= data_end && str_start <= file_len {
            data_end = (str_start + str_size.max(4)).min(file_len);
        }
    }
    if file_len > data_end {
        let mut size = file_len - data_end;
        if let Some(sig) = &info.signature
            && u64::from(sig.offset) >= data_end
        {
            size = size.saturating_sub(u64::from(sig.size));
        }
        if size > 0 {
            info.overlay = Some(Overlay {
                offset: data_end,
                size,
            });
        }
    }
    let checksum_off = pe.header.dos_header.pe_pointer as usize + 4 + 20 + 64;
    info.checksum_computed = pe_checksum(bytes, checksum_off);

    let kind = if coff.characteristics & IMAGE_FILE_DLL != 0 {
        FileKind::SharedLibrary
    } else if info.subsystem == 1 {
        FileKind::Driver
    } else if pe.header.optional_header.is_none() {
        FileKind::Object
    } else {
        FileKind::Executable
    };
    let os = if (10..=13).contains(&info.subsystem) {
        "UEFI"
    } else {
        "Windows"
    };
    let entry = (pe.entry != 0).then(|| image_base.wrapping_add(u64::from(pe.entry)));
    let file_size = data.file().len() as u64;
    let abi = Some(subsystem_name(info.subsystem).to_string());
    drop(pe);

    Ok(Binary {
        path,
        format: Format::Pe,
        kind,
        arch,
        bits,
        endian: Endian::Little,
        thumb,
        os: os.to_string(),
        abi,
        entry,
        image_base,
        file_size,
        sections,
        segments: Vec::new(),
        regions,
        symbols,
        imports,
        exports,
        relocations,
        libraries,
        interpreter: None,
        details: Details::Pe(Box::new(info)),
        warnings,
        data,
    })
}

/// Delay-load import descriptors (`ImgDelayDescr`), including the old VC6 form that
/// stores VAs instead of RVAs.
fn parse_delay_imports(
    bytes: &[u8],
    dir_rva: u64,
    image_base: u64,
    is64: bool,
    rva_off: &dyn Fn(u64) -> Option<usize>,
) -> Vec<Import> {
    let mut out = Vec::new();
    let Some(mut off) = rva_off(dir_rva) else {
        return out;
    };
    let ptr = if is64 { 8 } else { 4 };
    let ord_flag: u64 = if is64 { 1 << 63 } else { 1 << 31 };
    for _ in 0..4096 {
        let f = |i: usize| read_u32(bytes, off + i * 4, true);
        let (Some(attrs), Some(name_rva), Some(iat_rva), Some(int_rva)) = (f(0), f(1), f(3), f(4))
        else {
            break;
        };
        if name_rva == 0 && iat_rva == 0 && int_rva == 0 {
            break;
        }
        let to_rva = |v: u64| {
            if attrs & 1 == 1 {
                v
            } else {
                v.wrapping_sub(image_base)
            }
        };
        let lib = rva_off(to_rva(u64::from(name_rva)))
            .and_then(|o| cstr_at(bytes, o, 256))
            .filter(|s| !s.is_empty());
        let Some(int_off) = rva_off(to_rva(u64::from(int_rva))) else {
            off += 32;
            continue;
        };
        for i in 0..0x10000usize {
            let at = int_off + i * ptr;
            let entry = if is64 {
                read_u64(bytes, at, true)
            } else {
                read_u32(bytes, at, true).map(u64::from)
            };
            let Some(entry) = entry.filter(|&e| e != 0) else {
                break;
            };
            let (name, ordinal) = if entry & ord_flag != 0 {
                (None, Some((entry & 0xffff) as u32))
            } else {
                let name =
                    rva_off(to_rva(entry & 0x7fff_ffff)).and_then(|o| cstr_at(bytes, o + 2, 512));
                (name, None)
            };
            out.push(Import {
                demangled: name.as_deref().and_then(demangle),
                name,
                ordinal,
                library: lib.clone(),
                version: None,
                slot: Some(
                    image_base
                        .wrapping_add(to_rva(u64::from(iat_rva)))
                        .wrapping_add((i * ptr) as u64),
                ),
                plt: None,
                weak: false,
                delayed: true,
            });
        }
        off += 32;
    }
    out
}

/// `IMAGE_LOAD_CONFIG_DIRECTORY{32,64}`: a field is read only if it lies inside
/// the structure's own `Size` (older linkers emit shorter versions).
fn parse_load_config(
    bytes: &[u8],
    rva: u64,
    is64: bool,
    rva_off: &dyn Fn(u64) -> Option<usize>,
) -> Option<LoadConfig> {
    let base = rva_off(rva)?;
    let size = read_u32(bytes, base, true)?;
    let field = |at: usize, width: usize| -> u64 {
        if at + width > size as usize {
            return 0;
        }
        match width {
            8 => read_u64(bytes, base + at, true),
            _ => read_u32(bytes, base + at, true).map(u64::from),
        }
        .unwrap_or(0)
    };
    // (SecurityCookie, SEHandlerTable, SEHandlerCount, GuardCFCheckFunctionPointer,
    //  GuardCFFunctionCount, GuardFlags) offsets per layout.
    let (cookie, seh_table, seh_count, cf_check, cf_count, flags) = if is64 {
        (
            field(0x58, 8),
            field(0x60, 8),
            field(0x68, 8),
            field(0x70, 8),
            field(0x88, 8),
            field(0x90, 4),
        )
    } else {
        (
            field(0x3c, 4),
            field(0x40, 4),
            field(0x44, 4),
            field(0x48, 4),
            field(0x54, 4),
            field(0x58, 4),
        )
    };
    Some(LoadConfig {
        size,
        security_cookie: cookie,
        se_handler_table: seh_table,
        se_handler_count: seh_count,
        guard_flags: flags as u32,
        guard_cf_check_function: cf_check,
        guard_cf_function_count: cf_count,
    })
}

/// The PE image checksum algorithm (as computed by `CheckSumMappedFile`).
fn pe_checksum(bytes: &[u8], checksum_off: usize) -> u32 {
    let mut sum: u64 = 0;
    let (words, rest) = bytes.as_chunks::<2>();
    for (i, &w) in words.iter().enumerate() {
        let pos = i * 2;
        if pos == checksum_off || pos == checksum_off + 2 {
            continue;
        }
        sum += u64::from(u16::from_le_bytes(w));
    }
    if let [last] = rest {
        sum += u64::from(*last);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (sum as u32).wrapping_add(bytes.len() as u32)
}

fn format_guid(g: &[u8; 16]) -> String {
    let d1 = read_u32(g, 0, true).unwrap_or(0);
    let d2 = read_u16(g, 4, true).unwrap_or(0);
    let d3 = read_u16(g, 6, true).unwrap_or(0);
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

fn pe_arch(machine: u16) -> (Arch, bool) {
    match machine {
        0x014c => (Arch::X86, false),
        0x8664 => (Arch::X86_64, false),
        0x01c0 => (Arch::Arm, false),
        0x01c2 | 0x01c4 => (Arch::Arm, true),
        0xaa64 | 0xa641 | 0xa64e => (Arch::Arm64, false),
        0x5032 => (Arch::RiscV32, false),
        0x5064 => (Arch::RiscV64, false),
        0x0166 | 0x0169 => (Arch::Mips, false),
        0x01f0 | 0x01f1 => (Arch::PowerPc, false),
        0x6264 => (Arch::LoongArch64, false),
        0x0200 => (Arch::Unknown("ia64".into()), false),
        0x0ebc => (Arch::Unknown("efi-bytecode".into()), false),
        m => (Arch::Unknown(format!("pe-machine-{m:#06x}")), false),
    }
}

pub fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "native",
        2 => "GUI",
        3 => "console",
        5 => "OS/2 console",
        7 => "POSIX console",
        8 => "native Win9x driver",
        9 => "Windows CE GUI",
        10 => "EFI application",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => "unknown subsystem",
    }
}

fn base_reloc_name(t: u8, machine: u16) -> &'static str {
    let arm = matches!(machine, 0x01c0 | 0x01c2 | 0x01c4);
    let mips = matches!(machine, 0x0166 | 0x0169);
    let riscv = matches!(machine, 0x5032 | 0x5064);
    match t {
        1 => "HIGH",
        2 => "LOW",
        3 => "HIGHLOW",
        4 => "HIGHADJ",
        5 if arm => "ARM_MOV32",
        5 if mips => "MIPS_JMPADDR",
        5 if riscv => "RISCV_HIGH20",
        7 if arm => "THUMB_MOV32",
        7 if riscv => "RISCV_LOW12I",
        8 if riscv => "RISCV_LOW12S",
        9 if mips => "MIPS_JMPADDR16",
        9 => "IA64_IMM64",
        10 => "DIR64",
        _ => "MACHINE_SPECIFIC",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_reference_algorithm() {
        // Reference: byte-wise implementation with explicit carry folding.
        fn reference(b: &[u8], co: usize) -> u32 {
            let mut sum: u32 = 0;
            let mut i = 0;
            while i < b.len() {
                if i == co || i == co + 2 {
                    i += 2;
                    continue;
                }
                let lo = b[i] as u32;
                let hi = b.get(i + 1).copied().unwrap_or(0) as u32;
                sum += lo | (hi << 8);
                sum = (sum & 0xffff) + (sum >> 16);
                i += 2;
            }
            sum = (sum & 0xffff) + (sum >> 16);
            sum + b.len() as u32
        }
        let data: Vec<u8> = (0..5001u32).map(|i| (i * 7 + 3) as u8).collect();
        assert_eq!(pe_checksum(&data, 0xd8), reference(&data, 0xd8));
    }

    #[test]
    fn guid_formatting() {
        let g = [
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        assert_eq!(format_guid(&g), "12345678-9ABC-DEF0-0102-030405060708");
    }
}
