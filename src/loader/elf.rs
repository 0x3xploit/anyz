//! ELF loader (goblin) -> unified model.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use goblin::elf::{
    Elf, dynamic as dy, header as eh, program_header as ph, reloc, section_header as sh, sym,
};
use goblin::strtab::Strtab;

use super::{demangle, hex_string, read_u32};
use crate::model::*;

const SHN_UNDEF: usize = 0;
const SHN_ABS: usize = 0xfff1;
const SHN_COMMON: usize = 0xfff2;

const DF_TEXTREL: u64 = 0x4;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;
const DF_1_PIE: u64 = 0x0800_0000;

const NT_GNU_ABI_TAG: u32 = 1;
const NT_GNU_BUILD_ID: u32 = 3;
const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;

pub fn load(path: PathBuf, data: Data) -> Result<Binary> {
    let mut warnings = Vec::new();
    let bytes = data.slice();
    let elf = match Elf::parse(bytes) {
        Ok(e) => e,
        Err(strict) => {
            let opts = goblin::options::ParseOptions::permissive();
            match Elf::parse_with_opts(bytes, &opts) {
                Ok(e) => {
                    warnings.push(format!(
                        "malformed ELF ({strict}); parsed permissively, some data may be missing"
                    ));
                    e
                }
                Err(_) => return Err(anyhow!("invalid ELF file: {strict}")),
            }
        }
    };

    let hdr = &elf.header;
    let machine = hdr.e_machine;
    let bits: u8 = if elf.is_64 { 64 } else { 32 };
    let little = elf.little_endian;
    let endian = if little { Endian::Little } else { Endian::Big };
    let arch = elf_arch(machine, bits);
    let os_abi = hdr.e_ident[eh::EI_OSABI];
    let abi_version = hdr.e_ident[eh::EI_ABIVERSION];

    // ---- sections -------------------------------------------------------
    let mut sections = Vec::with_capacity(elf.section_headers.len());
    for (i, s) in elf.section_headers.iter().enumerate() {
        if i == 0 && s.sh_type == sh::SHT_NULL {
            continue;
        }
        let alloc = s.sh_flags & u64::from(sh::SHF_ALLOC) != 0;
        let nobits = s.sh_type == sh::SHT_NOBITS;
        sections.push(Section {
            index: i,
            name: elf.shdr_strtab.get_at(s.sh_name).unwrap_or("").to_string(),
            segment: None,
            addr: s.sh_addr,
            size: s.sh_size,
            offset: s.sh_offset,
            file_size: if nobits { 0 } else { s.sh_size },
            perms: Perms::new(
                alloc,
                s.sh_flags & u64::from(sh::SHF_WRITE) != 0,
                s.sh_flags & u64::from(sh::SHF_EXECINSTR) != 0,
            ),
            kind: section_type_name(s.sh_type),
            flags: s.sh_flags,
            alloc,
            tls: s.sh_flags & u64::from(sh::SHF_TLS) != 0,
        });
    }
    let section_name = |idx: usize| -> Option<String> {
        elf.section_headers
            .get(idx)
            .and_then(|s| elf.shdr_strtab.get_at(s.sh_name))
            .map(str::to_string)
    };

    // ---- segments / regions --------------------------------------------
    let mut segments = Vec::with_capacity(elf.program_headers.len());
    let mut regions = Vec::new();
    let mut gnu_stack = None;
    let mut gnu_relro = false;
    let mut has_dynamic = false;
    for (i, p) in elf.program_headers.iter().enumerate() {
        let perms = Perms::new(
            p.p_flags & ph::PF_R != 0,
            p.p_flags & ph::PF_W != 0,
            p.p_flags & ph::PF_X != 0,
        );
        match p.p_type {
            ph::PT_GNU_STACK => gnu_stack = Some(perms),
            ph::PT_GNU_RELRO => gnu_relro = true,
            ph::PT_DYNAMIC => has_dynamic = true,
            _ => {}
        }
        let loadable = p.p_type == ph::PT_LOAD;
        if loadable && p.p_memsz > 0 {
            regions.push(Region {
                name: format!("LOAD[{i}]"),
                va: p.p_vaddr,
                vsize: p.p_memsz,
                offset: p.p_offset,
                file_size: p.p_filesz.min(p.p_memsz),
                perms,
            });
        }
        segments.push(Segment {
            index: i,
            name: segment_type_name(p.p_type),
            kind: p.p_type,
            vaddr: p.p_vaddr,
            vsize: p.p_memsz,
            offset: p.p_offset,
            file_size: p.p_filesz,
            perms,
            max_perms: None,
            align: p.p_align,
            loadable,
        });
    }
    let image_base = regions
        .iter()
        .map(|r| r.va)
        .min()
        .map_or(0, |va| va & !0xfff);

    // ---- dynamic section -----------------------------------------------
    let mut dt_flags = 0;
    let mut dt_flags_1 = 0;
    let mut bind_now = false;
    let mut textrel = false;
    let mut dynamic = Vec::new();
    if let Some(d) = &elf.dynamic {
        for e in &d.dyns {
            match e.d_tag {
                dy::DT_FLAGS => dt_flags = e.d_val,
                dy::DT_FLAGS_1 => dt_flags_1 = e.d_val,
                dy::DT_BIND_NOW => bind_now = true,
                dy::DT_TEXTREL => textrel = true,
                _ => {}
            }
            dynamic.push(DynEntry {
                tag: e.d_tag,
                name: dy::tag_to_str(e.d_tag)
                    .trim_start_matches("DT_")
                    .to_string(),
                value: e.d_val,
            });
        }
    }
    bind_now |= dt_flags & DF_BIND_NOW != 0 || dt_flags_1 & DF_1_NOW != 0;
    textrel |= dt_flags & DF_TEXTREL != 0;

    // ---- symbol versions -----------------------------------------------
    // version index -> (version name, library that provides it)
    let mut versions: HashMap<u16, (String, Option<String>)> = HashMap::new();
    if let Some(vn) = &elf.verneed {
        for need in vn.iter() {
            let lib = elf.dynstrtab.get_at(need.vn_file).map(str::to_string);
            for aux in need.iter() {
                if let Some(name) = elf.dynstrtab.get_at(aux.vna_name) {
                    versions.insert(aux.vna_other, (name.to_string(), lib.clone()));
                }
            }
        }
    }
    if let Some(vd) = &elf.verdef {
        for def in vd.iter() {
            if def.vd_flags & 0x1 != 0 {
                continue; // VER_FLG_BASE: the file's own name
            }
            if let Some(aux) = def.iter().next()
                && let Some(name) = elf.dynstrtab.get_at(aux.vda_name)
            {
                versions
                    .entry(def.vd_ndx)
                    .or_insert((name.to_string(), None));
            }
        }
    }

    // ---- symbols ---------------------------------------------------------
    let is_arm = machine == eh::EM_ARM;
    let mut symbols = Vec::new();
    let mut seen: HashSet<(String, u64, bool)> = HashSet::new();
    let version_of = |idx: usize| -> Option<(String, Option<String>)> {
        elf.versym
            .as_ref()
            .and_then(|vs| vs.get_at(idx))
            .and_then(|v| versions.get(&v.version()))
            .cloned()
    };

    // ARM `$a`/`$t`/`$d` mapping symbols: which ranges are ARM, Thumb or data.
    let mut arm_mapping: Vec<(u64, char)> = Vec::new();
    let mut add_symbols = |table: &sym::Symtab, strtab: &Strtab, dynamic: bool| {
        for (idx, s) in table.iter().enumerate() {
            if idx == 0 {
                continue;
            }
            let st_type = s.st_type();
            if st_type == sym::STT_SECTION {
                continue;
            }
            let raw_name = strtab.get_at(s.st_name).unwrap_or("");
            if raw_name.is_empty() {
                continue;
            }
            if is_mapping_symbol(raw_name) {
                if is_arm && s.st_shndx != SHN_UNDEF {
                    arm_mapping.push((s.st_value & !1, char::from(raw_name.as_bytes()[1])));
                }
                continue;
            }
            let defined = s.st_shndx != SHN_UNDEF;
            let kind = sym_kind(st_type);
            let (addr, thumb) = if is_arm && kind == SymKind::Func && s.st_value & 1 == 1 {
                (s.st_value & !1, true)
            } else {
                (s.st_value, false)
            };
            let base_name = raw_name.split('@').next().unwrap_or(raw_name).to_string();
            if !seen.insert((base_name, addr, defined)) {
                continue;
            }
            let ver = if dynamic { version_of(idx) } else { None };
            let section = match s.st_shndx {
                SHN_UNDEF => None,
                SHN_ABS => Some("ABS".to_string()),
                SHN_COMMON => Some("COMMON".to_string()),
                n => section_name(n),
            };
            symbols.push(Symbol {
                demangled: demangle(raw_name),
                name: raw_name.to_string(),
                addr,
                size: s.st_size,
                kind,
                bind: sym_bind(s.st_bind()),
                section,
                defined,
                dynamic,
                version: ver.as_ref().map(|v| v.0.clone()),
                library: ver.and_then(|v| v.1),
                thumb,
            });
        }
    };
    add_symbols(&elf.dynsyms, &elf.dynstrtab, true);
    add_symbols(&elf.syms, &elf.strtab, false);

    // ---- imports / exports ----------------------------------------------
    // GOT slot per dynamic symbol index: JUMP_SLOT relocations win over GLOB_DAT.
    let mut slots: HashMap<usize, u64> = HashMap::new();
    for r in elf.pltrelocs.iter() {
        slots.entry(r.r_sym).or_insert(r.r_offset);
    }
    for r in elf.dynrelas.iter().chain(elf.dynrels.iter()) {
        if r.r_sym != 0 {
            slots.entry(r.r_sym).or_insert(r.r_offset);
        }
    }
    let sole_lib = (elf.libraries.len() == 1).then(|| elf.libraries[0].to_string());
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    for (idx, s) in elf.dynsyms.iter().enumerate() {
        if idx == 0 {
            continue;
        }
        let st_type = s.st_type();
        if matches!(st_type, sym::STT_SECTION | sym::STT_FILE) {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(s.st_name).filter(|n| !n.is_empty()) else {
            continue;
        };
        let ver = version_of(idx);
        let ver = ver.as_ref();
        if s.st_shndx == SHN_UNDEF {
            imports.push(Import {
                name: Some(name.to_string()),
                demangled: demangle(name),
                ordinal: None,
                library: ver.and_then(|v| v.1.clone()).or_else(|| sole_lib.clone()),
                version: ver.map(|v| v.0.clone()),
                slot: slots.get(&idx).copied(),
                plt: None,
                weak: s.st_bind() == sym::STB_WEAK,
                delayed: false,
            });
        } else if matches!(
            s.st_bind(),
            sym::STB_GLOBAL | sym::STB_WEAK | sym::STB_GNU_UNIQUE
        ) && matches!(s.st_visibility(), sym::STV_DEFAULT | sym::STV_PROTECTED)
        {
            let kind = sym_kind(st_type);
            let addr = if is_arm && kind == SymKind::Func {
                s.st_value & !1
            } else {
                s.st_value
            };
            exports.push(Export {
                name: Some(name.to_string()),
                demangled: demangle(name),
                addr,
                ordinal: None,
                forwarder: None,
                kind,
            });
        }
    }

    let gotplt = sections
        .iter()
        .find(|s| s.name == ".got.plt")
        .map(|s| s.addr)
        .or_else(|| elf.dynamic.as_ref().and_then(|d| d.info.pltgot));
    // Every GOT slot that a PLT stub may jump through, with its symbol: imports,
    // but also preemptible functions a shared library calls through its own PLT.
    let mut slot_names: HashMap<u64, String> = HashMap::new();
    for r in elf
        .pltrelocs
        .iter()
        .chain(elf.dynrelas.iter())
        .chain(elf.dynrels.iter())
    {
        if r.r_sym == 0 {
            continue;
        }
        if let Some(name) = elf
            .dynsyms
            .get(r.r_sym)
            .and_then(|s| elf.dynstrtab.get_at(s.st_name))
            .filter(|n| !n.is_empty())
        {
            slot_names
                .entry(r.r_offset)
                .or_insert_with(|| name.to_string());
        }
    }
    let plt = resolve_plt(machine, bits, little, &sections, bytes, gotplt, &slot_names);
    for imp in &mut imports {
        if let Some(slot) = imp.slot {
            imp.plt = plt.iter().find(|e| e.slot == slot).map(|e| e.addr);
        }
    }

    // ---- relocations -----------------------------------------------------
    let mut relocations = Vec::new();
    let mut push_relocs =
        |source: &str, rs: &reloc::RelocSection, syms: &sym::Symtab, strs: &Strtab| {
            for r in rs.iter() {
                let symbol = (r.r_sym != 0)
                    .then(|| syms.get(r.r_sym))
                    .flatten()
                    .and_then(|s| strs.get_at(s.st_name))
                    .filter(|n| !n.is_empty())
                    .map(str::to_string);
                relocations.push(Relocation {
                    addr: r.r_offset,
                    kind: reloc_name(r.r_type, machine),
                    raw_type: r.r_type,
                    symbol,
                    addend: r.r_addend,
                    source: source.to_string(),
                });
            }
        };
    if !elf.shdr_relocs.is_empty() {
        for (shndx, rs) in &elf.shdr_relocs {
            let link = elf
                .section_headers
                .get(*shndx)
                .map_or(0, |s| s.sh_link as usize);
            let uses_dynsym = elf
                .section_headers
                .get(link)
                .is_some_and(|s| s.sh_type == sh::SHT_DYNSYM);
            let name = section_name(*shndx).unwrap_or_else(|| format!("[{shndx}]"));
            if uses_dynsym {
                push_relocs(&name, rs, &elf.dynsyms, &elf.dynstrtab);
            } else {
                push_relocs(&name, rs, &elf.syms, &elf.strtab);
            }
        }
    } else {
        let dynname = if elf.dynrelas.is_empty() {
            ".rel.dyn"
        } else {
            ".rela.dyn"
        };
        push_relocs(dynname, &elf.dynrelas, &elf.dynsyms, &elf.dynstrtab);
        push_relocs(".rel.dyn", &elf.dynrels, &elf.dynsyms, &elf.dynstrtab);
        push_relocs(".rela.plt", &elf.pltrelocs, &elf.dynsyms, &elf.dynstrtab);
    }

    // ---- notes -----------------------------------------------------------
    let mut info = ElfInfo {
        class: bits,
        e_type: hdr.e_type,
        machine,
        os_abi,
        abi_version,
        flags: hdr.e_flags,
        has_section_headers: !elf.section_headers.is_empty(),
        has_symtab: elf
            .section_headers
            .iter()
            .any(|s| s.sh_type == sh::SHT_SYMTAB),
        has_dynsym: !elf.dynsyms.is_empty(),
        has_debug_info: sections
            .iter()
            .any(|s| s.name.starts_with(".debug_") || s.name.starts_with(".zdebug_")),
        has_dynamic,
        gnu_stack,
        gnu_relro,
        bind_now,
        dt_flags,
        dt_flags_1,
        textrel,
        soname: elf.soname.map(str::to_string),
        rpath: elf.rpaths.iter().map(|s| s.to_string()).collect(),
        runpath: elf.runpaths.iter().map(|s| s.to_string()).collect(),
        dynamic,
        arm_mapping: {
            arm_mapping.sort_unstable();
            arm_mapping
        },
        plt,
        ..Default::default()
    };
    let notes = if info.has_section_headers {
        elf.iter_note_sections(bytes, None)
    } else {
        elf.iter_note_headers(bytes)
    };
    if let Some(notes) = notes {
        for note in notes.flatten() {
            parse_note(&mut info, note.name, note.n_type, note.desc, little, bits);
        }
    }
    if let Some(c) = sections.iter().find(|s| s.name == ".comment") {
        let raw = clamp_slice(bytes, c.offset, c.file_size);
        for part in raw.split(|&b| b == 0) {
            let s = String::from_utf8_lossy(part).trim().to_string();
            if !s.is_empty() && !info.comment.contains(&s) {
                info.comment.push(s);
            }
        }
    }

    if !info.has_section_headers {
        warnings.push(
            "no section headers (stripped with sstrip, packed, or deliberately damaged)".into(),
        );
    }

    // ---- classification ----------------------------------------------------
    let interpreter = elf.interpreter.map(str::to_string);
    let kind = match hdr.e_type {
        eh::ET_EXEC => FileKind::Executable,
        eh::ET_DYN => {
            if dt_flags_1 & DF_1_PIE != 0 || (interpreter.is_some() && info.soname.is_none()) {
                FileKind::Executable
            } else {
                FileKind::SharedLibrary
            }
        }
        eh::ET_REL => FileKind::Object,
        eh::ET_CORE => FileKind::Core,
        _ => FileKind::Other,
    };
    let os = elf_os(&info, interpreter.as_deref());
    let entry = (elf.entry != 0).then_some(if is_arm { elf.entry & !1 } else { elf.entry });
    let thumb = is_arm && elf.entry & 1 == 1;
    let libraries = elf.libraries.iter().map(|s| s.to_string()).collect();
    let file_size = data.file().len() as u64;
    drop(elf);

    Ok(Binary {
        path,
        format: Format::Elf,
        kind,
        arch,
        bits,
        endian,
        thumb,
        os,
        abi: Some(os_abi_name(os_abi).to_string()),
        entry,
        image_base,
        file_size,
        sections,
        segments,
        regions,
        symbols,
        imports,
        exports,
        relocations,
        libraries,
        interpreter,
        details: Details::Elf(info),
        warnings,
        data,
    })
}

/// Map PLT stubs to imports by decoding each stub's indirect jump through its
/// GOT slot (the slot is already known from the JUMP_SLOT/GLOB_DAT relocation).
/// Decoding instead of assuming a layout copes with lazy `.plt`, CET `.plt.sec`,
/// `.plt.got` and the BFD/lld/gold variants.
fn resolve_plt(
    machine: u16,
    bits: u8,
    little: bool,
    sections: &[Section],
    bytes: &[u8],
    gotplt: Option<u64>,
    slot_names: &HashMap<u64, String>,
) -> Vec<PltEntry> {
    let mut entries = Vec::new();
    if slot_names.is_empty() {
        return entries;
    }
    for sec in sections.iter().filter(|s| {
        s.perms.x
            && matches!(
                s.name.as_str(),
                ".plt" | ".plt.sec" | ".plt.got" | ".plt.bnd" | ".iplt"
            )
    }) {
        let data = clamp_slice(bytes, sec.offset, sec.file_size);
        let mut stubs = Vec::new();
        match machine {
            eh::EM_X86_64 => plt_x86(sec.addr, data, None, &mut stubs),
            eh::EM_386 => plt_x86(sec.addr, data, Some(gotplt.unwrap_or(0)), &mut stubs),
            eh::EM_AARCH64 => plt_aarch64(sec.addr, data, little, &mut stubs),
            eh::EM_ARM => plt_arm(sec.addr, data, little, &mut stubs),
            eh::EM_RISCV => plt_riscv(sec.addr, data, bits, little, &mut stubs),
            _ => {}
        }
        for (addr, slot) in stubs {
            if let Some(name) = slot_names.get(&slot) {
                entries.push(PltEntry {
                    addr,
                    slot,
                    name: name.clone(),
                    section: sec.name.clone(),
                });
            }
        }
    }
    entries.sort_by_key(|e| e.addr);
    entries.dedup_by_key(|e| e.addr);
    entries
}

/// x86 / x86-64: `[endbr] [bnd] jmp *disp32(%rip)` (64-bit), `jmp *abs32` or
/// `jmp *disp32(%ebx)` (32-bit; `gotplt` is the GOT base held in %ebx).
fn plt_x86(base: u64, d: &[u8], gotplt: Option<u64>, out: &mut Vec<(u64, u64)>) {
    let mut p = 0;
    while p + 6 <= d.len() {
        let op = (d[p], d[p + 1]);
        let disp = i32::from_le_bytes([d[p + 2], d[p + 3], d[p + 4], d[p + 5]]);
        let slot = match (op, gotplt) {
            ((0xff, 0x25), None) => {
                Some((base + p as u64 + 6).wrapping_add_signed(i64::from(disp)))
            }
            ((0xff, 0x25), Some(_)) => Some(u64::from(disp as u32)),
            ((0xff, 0xa3), Some(got)) => {
                Some(got.wrapping_add_signed(i64::from(disp)) & 0xffff_ffff)
            }
            _ => None,
        };
        let Some(slot) = slot else {
            p += 1;
            continue;
        };
        let mut start = p;
        if start >= 1 && d[start - 1] == 0xf2 {
            start -= 1; // bnd prefix
        }
        if start >= 4 && matches!(d[start - 4..start], [0xf3, 0x0f, 0x1e, 0xfa | 0xfb]) {
            start -= 4; // endbr64 / endbr32
        }
        let stub = base + start as u64;
        if stub.is_multiple_of(8) {
            out.push((stub, slot));
        }
        p += 6;
    }
}

fn word(d: &[u8], p: usize, little: bool) -> Option<u32> {
    read_u32(d, p, little)
}

/// AArch64: `[bti c] adrp x16, page; ldr x17, [x16, #off]; add x16, x16, #off; br x17`.
fn plt_aarch64(base: u64, d: &[u8], little: bool, out: &mut Vec<(u64, u64)>) {
    let mut p = 0;
    while let (Some(w0), Some(w1)) = (word(d, p, little), word(d, p + 4, little)) {
        // adrp x16 / ldr x17, [x16, #imm12*8] (or ldr w17, [x16, #imm12*4] for ILP32)
        let ldr_scale = match w1 & 0xffc0_03ff {
            0xf940_0211 => Some(8),
            0xb940_0211 => Some(4),
            _ => None,
        };
        if w0 & 0x9f00_001f == 0x9000_0010
            && let Some(scale) = ldr_scale
        {
            let pc = base + p as u64;
            let immlo = u64::from((w0 >> 29) & 3);
            let immhi = u64::from((w0 >> 5) & 0x7ffff);
            let imm = sign_extend((immhi << 2) | immlo, 21) << 12;
            let page = (pc & !0xfff).wrapping_add(imm);
            let slot = page.wrapping_add(u64::from((w1 >> 10) & 0xfff) * scale);
            let start = if p >= 4 && word(d, p - 4, little) == Some(0xd503_245f) {
                p - 4
            } else {
                p
            };
            out.push((base + start as u64, slot));
            p += 16;
            continue;
        }
        p += 4;
    }
}

/// ARM: `add ip, pc, #a; add ip, ip, #b; ldr pc, [ip, #c]!` with rotated immediates.
fn plt_arm(base: u64, d: &[u8], little: bool, out: &mut Vec<(u64, u64)>) {
    let rot_imm = |w: u32| (w & 0xff).rotate_right(((w >> 8) & 0xf) * 2);
    let mut p = 0;
    while let (Some(w0), Some(w1), Some(w2)) = (
        word(d, p, little),
        word(d, p + 4, little),
        word(d, p + 8, little),
    ) {
        if w0 & 0xffff_f000 == 0xe28f_c000
            && w1 & 0xffff_f000 == 0xe28c_c000
            && w2 & 0xffff_f000 == 0xe5bc_f000
        {
            let pc = base + p as u64 + 8;
            let slot = pc + u64::from(rot_imm(w0)) + u64::from(rot_imm(w1)) + u64::from(w2 & 0xfff);
            out.push((base + p as u64, slot & 0xffff_ffff));
            p += 12;
            continue;
        }
        p += 4;
    }
}

/// RISC-V: `auipc t3, hi; l{d,w} t3, lo(t3); jalr t1, t3; nop`.
fn plt_riscv(base: u64, d: &[u8], bits: u8, little: bool, out: &mut Vec<(u64, u64)>) {
    let load = if bits == 64 { 0x000e_3e03 } else { 0x000e_2e03 };
    let mut p = 0;
    while let (Some(w0), Some(w1)) = (word(d, p, little), word(d, p + 4, little)) {
        if w0 & 0xfff == 0xe17 && w1 & 0xfffff == load {
            let pc = base + p as u64;
            let hi = i64::from((w0 & 0xffff_f000) as i32);
            let lo = i64::from((w1 as i32) >> 20);
            let mut slot = pc.wrapping_add_signed(hi + lo);
            if bits == 32 {
                slot &= 0xffff_ffff;
            }
            out.push((pc, slot));
            p += 16;
            continue;
        }
        p += 4;
    }
}

/// readelf-style relocation type name (`R_X86_64_JUMP_SLOT`), hex if unknown.
fn reloc_name(r_type: u32, machine: u16) -> String {
    let name = reloc::r_to_str(r_type, machine);
    if name.is_empty() || name.starts_with("UNKNOWN") {
        format!("{r_type:#x}")
    } else if name.starts_with("R_") {
        name.to_string()
    } else {
        format!("R_{name}")
    }
}

fn sign_extend(v: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((v << shift) as i64) >> shift) as u64
}

fn parse_note(info: &mut ElfInfo, name: &str, n_type: u32, desc: &[u8], le: bool, bits: u8) {
    match (name, n_type) {
        ("GNU", NT_GNU_BUILD_ID) => info.build_id = Some(hex_string(desc)),
        ("GNU", NT_GNU_ABI_TAG) if desc.len() >= 16 => {
            let w = |i: usize| read_u32(desc, i * 4, le).unwrap_or(0);
            let os = match w(0) {
                0 => "Linux",
                1 => "Hurd",
                2 => "Solaris",
                3 => "FreeBSD",
                4 => "NetBSD",
                5 => "Syllable",
                6 => "NaCl",
                _ => "unknown OS",
            };
            info.abi_tag = Some(format!("{os} {}.{}.{}", w(1), w(2), w(3)));
        }
        ("GNU", NT_GNU_PROPERTY_TYPE_0) => {
            let align = if bits == 64 { 8 } else { 4 };
            let mut off = 0usize;
            while let (Some(pr_type), Some(pr_size)) =
                (read_u32(desc, off, le), read_u32(desc, off + 4, le))
            {
                let data_off = off + 8;
                let value = read_u32(desc, data_off, le);
                match pr_type {
                    GNU_PROPERTY_X86_FEATURE_1_AND => info.x86_features = value,
                    GNU_PROPERTY_AARCH64_FEATURE_1_AND => info.aarch64_features = value,
                    _ => {}
                }
                let Some(next) = (pr_size as usize)
                    .checked_add(align - 1)
                    .and_then(|n| data_off.checked_add(n & !(align - 1)))
                else {
                    break;
                };
                if next <= off {
                    break;
                }
                off = next;
            }
        }
        ("Android", 1) => info.android_api = read_u32(desc, 0, le),
        ("Go", 4) => {
            let s = String::from_utf8_lossy(desc)
                .trim_end_matches('\0')
                .to_string();
            info.go_build_id = Some(s);
        }
        _ => {}
    }
}

fn elf_os(info: &ElfInfo, interp: Option<&str>) -> String {
    let interp = interp.unwrap_or("");
    if info.android_api.is_some() || interp.starts_with("/system/bin/linker") {
        return match info.android_api {
            Some(api) => format!("Android (API {api})"),
            None => "Android".into(),
        };
    }
    if let Some(tag) = &info.abi_tag
        && let Some(os) = tag.split(' ').next()
    {
        return os.to_string();
    }
    match info.os_abi {
        3 => return "Linux".into(),
        1 => return "HP-UX".into(),
        2 => return "NetBSD".into(),
        6 => return "Solaris".into(),
        9 => return "FreeBSD".into(),
        12 => return "OpenBSD".into(),
        _ => {}
    }
    if interp.contains("ld-linux") || interp.contains("ld-musl") || interp.contains("/ld64.so") {
        return "Linux".into();
    }
    if interp.contains("ld-elf.so") {
        return "FreeBSD".into();
    }
    if interp.contains("/usr/libexec/ld.so") {
        return "OpenBSD".into();
    }
    if info.x86_features.is_some() || info.go_build_id.is_some() || info.e_type == eh::ET_EXEC {
        // GNU property notes and Go/static executables without other hints are
        // overwhelmingly Linux.
        return "Linux".into();
    }
    "Unix (System V ABI)".into()
}

fn os_abi_name(v: u8) -> &'static str {
    match v {
        0 => "SYSV",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "GNU",
        6 => "Solaris",
        7 => "AIX",
        8 => "IRIX",
        9 => "FreeBSD",
        10 => "Tru64",
        11 => "Novell Modesto",
        12 => "OpenBSD",
        64 => "ARM EABI",
        97 => "ARM",
        255 => "Standalone",
        _ => "unknown",
    }
}

fn elf_arch(machine: u16, bits: u8) -> Arch {
    match machine {
        eh::EM_386 => Arch::X86,
        eh::EM_X86_64 => Arch::X86_64,
        eh::EM_ARM => Arch::Arm,
        eh::EM_AARCH64 => Arch::Arm64,
        eh::EM_MIPS | eh::EM_MIPS_RS3_LE => {
            if bits == 64 {
                Arch::Mips64
            } else {
                Arch::Mips
            }
        }
        eh::EM_RISCV => {
            if bits == 64 {
                Arch::RiscV64
            } else {
                Arch::RiscV32
            }
        }
        eh::EM_PPC => Arch::PowerPc,
        eh::EM_PPC64 => Arch::PowerPc64,
        eh::EM_SPARC | eh::EM_SPARC32PLUS => Arch::Sparc,
        eh::EM_SPARCV9 => Arch::Sparc64,
        eh::EM_68K => Arch::M68k,
        eh::EM_S390 if bits == 64 => Arch::S390x,
        eh::EM_BPF => Arch::Bpf,
        258 if bits == 64 => Arch::LoongArch64,
        m => {
            let name = eh::machine_to_str(m);
            if name.is_empty() || name.eq_ignore_ascii_case("unknown") {
                Arch::Unknown(format!("elf-machine-{m:#x}"))
            } else {
                Arch::Unknown(name.to_ascii_lowercase())
            }
        }
    }
}

fn sym_kind(t: u8) -> SymKind {
    match t {
        sym::STT_FUNC => SymKind::Func,
        sym::STT_OBJECT => SymKind::Object,
        sym::STT_TLS => SymKind::Tls,
        sym::STT_COMMON => SymKind::Common,
        sym::STT_GNU_IFUNC => SymKind::Ifunc,
        sym::STT_FILE => SymKind::File,
        sym::STT_SECTION => SymKind::Section,
        _ => SymKind::NoType,
    }
}

fn sym_bind(b: u8) -> SymBind {
    match b {
        sym::STB_LOCAL => SymBind::Local,
        sym::STB_GLOBAL => SymBind::Global,
        sym::STB_WEAK => SymBind::Weak,
        sym::STB_GNU_UNIQUE => SymBind::Unique,
        _ => SymBind::Unknown,
    }
}

/// ARM/AArch64/RISC-V mapping symbols (`$a`, `$t`, `$d`, `$x`, `$a.0`...).
fn is_mapping_symbol(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 2
        && b[0] == b'$'
        && matches!(b[1], b'a' | b't' | b'd' | b'x')
        && (b.len() == 2 || b[2] == b'.')
}

fn section_type_name(t: u32) -> String {
    let name = sh::sht_to_str(t);
    if name.starts_with("UNKNOWN") || name.is_empty() {
        format!("{t:#x}")
    } else {
        name.trim_start_matches("SHT_").to_string()
    }
}

fn segment_type_name(t: u32) -> String {
    match t {
        0x6474_e553 => "GNU_PROPERTY".into(),
        0x6474_e554 => "GNU_SFRAME".into(),
        _ => {
            let name = ph::pt_to_str(t);
            if name.starts_with("UNKNOWN") || name.is_empty() {
                format!("{t:#x}")
            } else {
                name.trim_start_matches("PT_").to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_symbols() {
        assert!(is_mapping_symbol("$a"));
        assert!(is_mapping_symbol("$t.12"));
        assert!(is_mapping_symbol("$x"));
        assert!(!is_mapping_symbol("$foo"));
        assert!(!is_mapping_symbol("main"));
    }

    #[test]
    fn gnu_property_note_is_parsed() {
        // x86 feature_1_and = IBT|SHSTK, 64-bit padding
        let mut desc = Vec::new();
        desc.extend_from_slice(&GNU_PROPERTY_X86_FEATURE_1_AND.to_le_bytes());
        desc.extend_from_slice(&4u32.to_le_bytes());
        desc.extend_from_slice(&3u32.to_le_bytes());
        desc.extend_from_slice(&0u32.to_le_bytes());
        let mut info = ElfInfo::default();
        parse_note(&mut info, "GNU", NT_GNU_PROPERTY_TYPE_0, &desc, true, 64);
        assert_eq!(info.x86_features, Some(3));
    }

    #[test]
    fn abi_tag_note_is_parsed() {
        let desc: Vec<u8> = [0u32, 3, 2, 0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let mut info = ElfInfo::default();
        parse_note(&mut info, "GNU", NT_GNU_ABI_TAG, &desc, true, 64);
        assert_eq!(info.abi_tag.as_deref(), Some("Linux 3.2.0"));
    }
}
