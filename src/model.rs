//! Unified, format-agnostic description of a binary.
//!
//! Loaders (`crate::loader`) translate ELF / PE / Mach-O / raw data into a [`Binary`];
//! analyzers only ever look at this model, never at goblin types.
//!
//! Address conventions used everywhere in the model:
//! * every stored address is an absolute **virtual address** (VA);
//! * **RVA** = VA - [`Binary::image_base`];
//! * **file offsets** are relative to [`Binary::bytes`] (for a fat Mach-O that is the
//!   selected slice, otherwise the whole file).
//!
//! VA <-> offset translation goes exclusively through [`Binary::regions`], the list of
//! file-backed memory mappings built by the loader.

use std::fmt;
use std::ops::{Deref, Range};
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Serialize, Serializer};

// ---------------------------------------------------------------------------
// Basic enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Elf,
    Pe,
    Macho,
    Raw,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Elf => "ELF",
            Format::Pe => "PE",
            Format::Macho => "Mach-O",
            Format::Raw => "raw",
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Mips64,
    RiscV32,
    RiscV64,
    PowerPc,
    PowerPc64,
    Sparc,
    Sparc64,
    M68k,
    S390x,
    LoongArch64,
    Bpf,
    Unknown(String),
}

impl Arch {
    pub fn name(&self) -> &str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86-64",
            Arch::Arm => "arm",
            Arch::Arm64 => "arm64",
            Arch::Mips => "mips",
            Arch::Mips64 => "mips64",
            Arch::RiscV32 => "riscv32",
            Arch::RiscV64 => "riscv64",
            Arch::PowerPc => "ppc",
            Arch::PowerPc64 => "ppc64",
            Arch::Sparc => "sparc",
            Arch::Sparc64 => "sparc64",
            Arch::M68k => "m68k",
            Arch::S390x => "s390x",
            Arch::LoongArch64 => "loongarch64",
            Arch::Bpf => "bpf",
            Arch::Unknown(s) => s,
        }
    }

    pub fn default_bits(&self) -> u8 {
        match self {
            Arch::X86 | Arch::Arm | Arch::Mips | Arch::RiscV32 | Arch::PowerPc | Arch::Sparc => 32,
            Arch::M68k => 32,
            Arch::Unknown(_) => 64,
            _ => 64,
        }
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Arch::Unknown(_))
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Serialize for Arch {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    pub fn name(self) -> &'static str {
        match self {
            Endian::Little => "little-endian",
            Endian::Big => "big-endian",
        }
    }
}

/// Architecture selected by the user (`--arch`) for raw blobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchSpec {
    pub arch: Arch,
    pub bits: u8,
    pub endian: Endian,
    pub thumb: bool,
}

impl ArchSpec {
    /// Accepted spellings, for help/error messages.
    pub const NAMES: &'static str = "x86, x86-64, arm, armbe, thumb, arm64, mips, mipsel, mips64, \
         mips64el, riscv32, riscv64, ppc, ppc64, ppc64le, sparc, sparc64, m68k, s390x, loongarch64";

    pub fn parse(s: &str) -> Option<ArchSpec> {
        use Arch::*;
        use Endian::*;
        let s = s.trim().to_ascii_lowercase().replace('_', "-");
        let (arch, endian, thumb) = match s.as_str() {
            "x86" | "i386" | "i486" | "i586" | "i686" | "x86-32" | "ia32" => (X86, Little, false),
            "x86-64" | "x64" | "amd64" => (X86_64, Little, false),
            "arm" | "arm32" | "armv7" | "armv7a" | "armel" | "armle" => (Arm, Little, false),
            "armbe" | "armeb" => (Arm, Big, false),
            "thumb" | "thumb2" | "thumbv7" => (Arm, Little, true),
            "arm64" | "aarch64" | "armv8" | "arm64e" => (Arm64, Little, false),
            "mips" | "mips32" | "mipsbe" | "mipseb" => (Mips, Big, false),
            "mipsel" | "mipsle" | "mips32el" => (Mips, Little, false),
            "mips64" | "mips64be" | "mips64eb" => (Mips64, Big, false),
            "mips64el" | "mips64le" => (Mips64, Little, false),
            "riscv32" | "rv32" => (RiscV32, Little, false),
            "riscv64" | "rv64" | "riscv" => (RiscV64, Little, false),
            "ppc" | "powerpc" | "ppc32" => (PowerPc, Big, false),
            "ppc64" | "powerpc64" => (PowerPc64, Big, false),
            "ppc64le" | "powerpc64le" => (PowerPc64, Little, false),
            "sparc" => (Sparc, Big, false),
            "sparc64" | "sparcv9" => (Sparc64, Big, false),
            "m68k" | "68k" => (M68k, Big, false),
            "s390x" | "systemz" => (S390x, Big, false),
            "loongarch64" | "loong64" => (LoongArch64, Little, false),
            _ => return None,
        };
        Some(ArchSpec {
            bits: arch.default_bits(),
            arch,
            endian,
            thumb,
        })
    }
}

/// Coarse file type. Format-specific detail (PIE vs shared object, kext, ...) is
/// derived by analyzers from [`Details`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Executable,
    SharedLibrary,
    Object,
    Core,
    Driver,
    Other,
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Perms {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

impl Perms {
    pub const fn new(r: bool, w: bool, x: bool) -> Self {
        Perms { r, w, x }
    }

    /// Writable and executable at the same time.
    pub fn is_wx(self) -> bool {
        self.w && self.x
    }

    pub fn is_rwx(self) -> bool {
        self.r && self.w && self.x
    }
}

impl fmt::Display for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = |on: bool, ch: char| if on { ch } else { '-' };
        write!(f, "{}{}{}", c(self.r, 'r'), c(self.w, 'w'), c(self.x, 'x'))
    }
}

impl Serialize for Perms {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

// ---------------------------------------------------------------------------
// Sections, segments, regions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    /// Index in the format's own numbering (ELF shndx, PE/Mach-O 1-based ordinal).
    pub index: usize,
    pub name: String,
    /// Owning segment (Mach-O only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segment: Option<String>,
    /// Virtual address (0 if the section is not loaded).
    pub addr: u64,
    /// Size in memory.
    pub size: u64,
    /// File offset of the section data.
    pub offset: u64,
    /// Bytes present in the file (0 for .bss / zerofill / NOBITS).
    pub file_size: u64,
    pub perms: Perms,
    /// Format-specific type, e.g. `PROGBITS`, `code`, `cstring_literals`.
    pub kind: String,
    /// Raw format-specific flags (sh_flags, Characteristics, Mach-O flags).
    pub flags: u64,
    /// Occupies memory at runtime.
    pub alloc: bool,
    /// Thread-local template (ELF .tdata/.tbss); its VA range overlaps other sections.
    pub tls: bool,
}

impl Section {
    /// `__TEXT,__text` for Mach-O, plain name otherwise.
    pub fn full_name(&self) -> String {
        match &self.segment {
            Some(seg) if !seg.is_empty() => format!("{seg},{}", self.name),
            _ => self.name.clone(),
        }
    }

    pub fn contains_va(&self, va: u64) -> bool {
        self.alloc && self.size > 0 && va >= self.addr && va - self.addr < self.size
    }

    pub fn contains_offset(&self, off: u64) -> bool {
        self.file_size > 0 && off >= self.offset && off - self.offset < self.file_size
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Segment {
    pub index: usize,
    /// ELF program header type (`LOAD`, `GNU_STACK`, ...) or Mach-O segment name.
    pub name: String,
    /// Raw type: ELF `p_type`, Mach-O load command id.
    pub kind: u32,
    pub vaddr: u64,
    pub vsize: u64,
    pub offset: u64,
    pub file_size: u64,
    pub perms: Perms,
    /// Mach-O `maxprot`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_perms: Option<Perms>,
    pub align: u64,
    /// Mapped into memory by the loader (PT_LOAD / any Mach-O segment).
    pub loadable: bool,
}

/// One contiguous file-backed mapping: `[va, va+vsize)` in memory, the first
/// `file_size` bytes of which come from `[offset, offset+file_size)` in the file.
#[derive(Debug, Clone, Serialize)]
pub struct Region {
    pub name: String,
    pub va: u64,
    pub vsize: u64,
    pub offset: u64,
    pub file_size: u64,
    pub perms: Perms,
}

impl Region {
    pub fn contains_va(&self, va: u64) -> bool {
        va >= self.va && va - self.va < self.vsize
    }
}

// ---------------------------------------------------------------------------
// Symbols, imports, exports, relocations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SymKind {
    Func,
    Object,
    Tls,
    Common,
    Ifunc,
    File,
    Section,
    NoType,
}

impl SymKind {
    pub fn name(self) -> &'static str {
        match self {
            SymKind::Func => "FUNC",
            SymKind::Object => "OBJECT",
            SymKind::Tls => "TLS",
            SymKind::Common => "COMMON",
            SymKind::Ifunc => "IFUNC",
            SymKind::File => "FILE",
            SymKind::Section => "SECTION",
            SymKind::NoType => "NOTYPE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SymBind {
    Local,
    Global,
    Weak,
    Unique,
    Unknown,
}

impl SymBind {
    pub fn name(self) -> &'static str {
        match self {
            SymBind::Local => "LOCAL",
            SymBind::Global => "GLOBAL",
            SymBind::Weak => "WEAK",
            SymBind::Unique => "UNIQUE",
            SymBind::Unknown => "?",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    pub addr: u64,
    pub size: u64,
    pub kind: SymKind,
    pub bind: SymBind,
    /// Containing section name; `None` for undefined symbols.
    pub section: Option<String>,
    /// `false` for undefined (imported) symbols.
    pub defined: bool,
    /// Comes from the dynamic symbol table / export directory.
    pub dynamic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    /// ARM Thumb function.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub thumb: bool,
}

impl Symbol {
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Import {
    /// `None` when imported by ordinal only.
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    pub library: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Pointer slot filled by the dynamic loader (PE IAT entry, ELF GOT entry,
    /// Mach-O lazy/non-lazy pointer).
    pub slot: Option<u64>,
    /// Call stub (ELF PLT entry, Mach-O `__stubs` entry).
    pub plt: Option<u64>,
    pub weak: bool,
    /// PE delay-load import.
    pub delayed: bool,
}

impl Import {
    /// Function name, or `ordinal N` for by-ordinal imports.
    pub fn label(&self) -> String {
        match (&self.name, self.ordinal) {
            (Some(n), _) => n.clone(),
            (None, Some(o)) => format!("ordinal {o}"),
            (None, None) => "?".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Export {
    /// `None` for PE exports by ordinal only.
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    /// VA; 0 for forwarders.
    pub addr: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    /// PE forwarder (`KERNEL32.GetTickCount`) or Mach-O re-export (`lib:symbol`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarder: Option<String>,
    pub kind: SymKind,
}

#[derive(Debug, Clone, Serialize)]
pub struct Relocation {
    /// VA patched by the relocation.
    pub addr: u64,
    /// Type name, e.g. `R_X86_64_JUMP_SLOT`, `DIR64`.
    pub kind: String,
    pub raw_type: u32,
    pub symbol: Option<String>,
    pub addend: Option<i64>,
    /// Relocation table it came from (`.rela.plt`, `.reloc`, ...).
    pub source: String,
}

// ---------------------------------------------------------------------------
// Format-specific facts (raw material for analyzers such as checksec)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "format", rename_all = "lowercase")]
pub enum Details {
    Elf(ElfInfo),
    Pe(Box<PeInfo>),
    Macho(MachoInfo),
    Raw(RawInfo),
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ElfInfo {
    pub class: u8,
    pub e_type: u16,
    pub machine: u16,
    pub os_abi: u8,
    pub abi_version: u8,
    pub flags: u32,
    pub has_section_headers: bool,
    pub has_symtab: bool,
    pub has_dynsym: bool,
    pub has_debug_info: bool,
    /// PT_DYNAMIC present.
    pub has_dynamic: bool,
    /// Permissions of PT_GNU_STACK; `None` when the header is absent.
    pub gnu_stack: Option<Perms>,
    /// PT_GNU_RELRO present.
    pub gnu_relro: bool,
    /// DT_BIND_NOW, DF_BIND_NOW or DF_1_NOW.
    pub bind_now: bool,
    pub dt_flags: u64,
    pub dt_flags_1: u64,
    pub textrel: bool,
    pub soname: Option<String>,
    pub rpath: Vec<String>,
    pub runpath: Vec<String>,
    pub build_id: Option<String>,
    /// From .note.ABI-tag, e.g. `Linux 3.2.0`.
    pub abi_tag: Option<String>,
    pub android_api: Option<u32>,
    pub go_build_id: Option<String>,
    /// GNU_PROPERTY_X86_FEATURE_1_AND (bit 0 IBT, bit 1 SHSTK).
    pub x86_features: Option<u32>,
    /// GNU_PROPERTY_AARCH64_FEATURE_1_AND (bit 0 BTI, bit 1 PAC).
    pub aarch64_features: Option<u32>,
    /// Strings from the .comment section (compiler / linker identification).
    pub comment: Vec<String>,
    /// ARM mapping symbols (`$a` ARM, `$t` Thumb, `$d` data) sorted by address.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arm_mapping: Vec<(u64, char)>,
    /// PLT stubs decoded from .plt/.plt.sec/.plt.got, sorted by address.
    pub plt: Vec<PltEntry>,
    pub dynamic: Vec<DynEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PltEntry {
    /// Stub address (what `call` targets).
    pub addr: u64,
    /// GOT slot the stub jumps through.
    pub slot: u64,
    pub name: String,
    pub section: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DynEntry {
    pub tag: u64,
    pub name: String,
    pub value: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PeInfo {
    /// PE32+ (64-bit optional header).
    pub pe32_plus: bool,
    pub machine: u16,
    pub characteristics: u16,
    pub dll_characteristics: u16,
    pub subsystem: u16,
    pub timestamp: u32,
    pub linker_version: (u8, u8),
    pub os_version: (u16, u16),
    pub subsystem_version: (u16, u16),
    pub checksum: u32,
    pub checksum_computed: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub data_directories: Vec<DataDir>,
    pub load_config: Option<LoadConfig>,
    pub signature: Option<Signature>,
    pub pdb: Option<PdbInfo>,
    /// `IMAGE_DEBUG_TYPE_REPRO`: the timestamp is a hash, not a date.
    pub reproducible: bool,
    pub has_rich_header: bool,
    pub rich: Vec<RichEntry>,
    pub clr: Option<ClrInfo>,
    pub tls_callbacks: Vec<u64>,
    pub ex_dll_characteristics: Option<u32>,
    /// Number of /GS-protected functions recorded in the VC feature debug entry.
    pub gs_functions: Option<u32>,
    pub has_coff_symbols: bool,
    pub overlay: Option<Overlay>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataDir {
    pub index: usize,
    pub name: &'static str,
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LoadConfig {
    pub size: u32,
    pub security_cookie: u64,
    pub se_handler_table: u64,
    pub se_handler_count: u64,
    pub guard_flags: u32,
    pub guard_cf_check_function: u64,
    pub guard_cf_function_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Signature {
    /// File offset of the attribute certificate table.
    pub offset: u32,
    pub size: u32,
    pub certificates: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PdbInfo {
    pub path: String,
    pub guid: String,
    pub age: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RichEntry {
    pub product: u16,
    pub build: u16,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClrInfo {
    pub runtime_version: String,
    pub metadata_version: Option<String>,
    pub flags: u32,
    pub il_only: bool,
    pub requires_32bit: bool,
    pub strong_name_signed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Overlay {
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MachoInfo {
    pub cputype: u32,
    pub cpusubtype: u32,
    /// Human-readable CPU subtype, e.g. `arm64e`, `x86_64h`.
    pub cpu_name: String,
    pub filetype: u32,
    pub flags: u32,
    pub ncmds: u32,
    pub code_signature: Option<CodeSignature>,
    pub encryption: Option<Encryption>,
    pub uuid: Option<String>,
    pub platform: Option<String>,
    pub min_os: Option<String>,
    pub sdk: Option<String>,
    pub build_tools: Vec<String>,
    pub source_version: Option<String>,
    pub rpaths: Vec<String>,
    pub chained_fixups: bool,
    pub dyld_info: bool,
    /// Symbol table contains STABS debug entries.
    pub has_stabs: bool,
    pub fat: Option<FatInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeSignature {
    /// Offset of the signature SuperBlob inside the image.
    pub offset: u32,
    pub size: u32,
    /// CodeDirectory flags (CS_ADHOC 0x2, CS_RUNTIME 0x10000, ...), when readable.
    pub flags: Option<u32>,
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    /// A non-empty CMS (certificate) signature blob is present.
    pub has_cms: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Encryption {
    pub cryptid: u32,
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FatInfo {
    pub slices: Vec<FatSlice>,
    pub selected: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FatSlice {
    pub arch: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RawInfo {
    /// Recognised non-executable container, e.g. `ZIP archive`.
    pub magic: Option<String>,
    /// `--arch` was given.
    pub arch_specified: bool,
}

// ---------------------------------------------------------------------------
// Raw bytes
// ---------------------------------------------------------------------------

pub enum Buffer {
    Mapped(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl Deref for Buffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Buffer::Mapped(m) => m,
            Buffer::Owned(v) => v,
        }
    }
}

/// Shared handle on the file contents plus the byte range this binary covers.
#[derive(Clone)]
pub struct Data {
    buf: Arc<Buffer>,
    range: Range<usize>,
}

impl Data {
    pub fn new(buf: Buffer) -> Self {
        let len = buf.len();
        Data {
            buf: Arc::new(buf),
            range: 0..len,
        }
    }

    pub fn from_vec(v: Vec<u8>) -> Self {
        Data::new(Buffer::Owned(v))
    }

    /// The whole file.
    pub fn file(&self) -> &[u8] {
        &self.buf
    }

    /// The bytes of this binary (a fat slice, or the whole file).
    pub fn slice(&self) -> &[u8] {
        self.buf.get(self.range.clone()).unwrap_or(&[])
    }

    /// Offset of [`Data::slice`] inside the file.
    pub fn slice_start(&self) -> usize {
        self.range.start
    }

    /// Narrow to `range` of the underlying file; `None` if out of bounds.
    pub fn sub(&self, range: Range<usize>) -> Option<Data> {
        (range.start <= range.end && range.end <= self.buf.len()).then(|| Data {
            buf: Arc::clone(&self.buf),
            range,
        })
    }
}

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Data({} bytes, range {:?})", self.buf.len(), self.range)
    }
}

// ---------------------------------------------------------------------------
// The binary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Binary {
    pub path: PathBuf,
    pub format: Format,
    pub kind: FileKind,
    pub arch: Arch,
    pub bits: u8,
    pub endian: Endian,
    /// Default ARM instruction set is Thumb (PE ARMNT, odd ELF entry, `--arch thumb`).
    pub thumb: bool,
    pub os: String,
    pub abi: Option<String>,
    pub entry: Option<u64>,
    pub image_base: u64,
    /// Size of the whole file on disk.
    pub file_size: u64,
    pub sections: Vec<Section>,
    pub segments: Vec<Segment>,
    pub regions: Vec<Region>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocations: Vec<Relocation>,
    pub libraries: Vec<String>,
    pub interpreter: Option<String>,
    pub details: Details,
    /// Non-fatal problems found while loading.
    pub warnings: Vec<String>,
    pub data: Data,
}

/// Why an address could not be translated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddrError {
    #[error("address {0:#x} is not inside any mapped section or segment")]
    Unmapped(u64),
    #[error("address {va:#x} is in {region}, which has no file backing (zero-filled at load time)")]
    NoFileBacking { va: u64, region: String },
    #[error("file offset {off:#x} is past the end of the file ({size:#x} bytes)")]
    OffsetPastEnd { off: u64, size: u64 },
    #[error("file offset {0:#x} is not loaded into memory (headers, debug info or overlay data)")]
    OffsetNotMapped(u64),
    #[error("address {va:#x} is below the image base {base:#x}, so it has no RVA")]
    BelowBase { va: u64, base: u64 },
    #[error("address arithmetic overflowed")]
    Overflow,
}

impl Binary {
    /// Bytes of this binary (selected slice for fat Mach-O).
    pub fn bytes(&self) -> &[u8] {
        self.data.slice()
    }

    /// Bytes of the whole file (hashes are computed over this).
    pub fn file_bytes(&self) -> &[u8] {
        self.data.file()
    }

    pub fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.display().to_string())
    }

    pub fn region_for_va(&self, va: u64) -> Option<&Region> {
        self.regions.iter().find(|r| r.contains_va(va))
    }

    /// Section containing `va`; TLS templates (which overlap other sections) lose ties.
    pub fn section_for_va(&self, va: u64) -> Option<&Section> {
        let mut found = None;
        for s in self.sections.iter().filter(|s| s.contains_va(va)) {
            if !s.tls {
                return Some(s);
            }
            found.get_or_insert(s);
        }
        found
    }

    pub fn section_for_offset(&self, off: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_offset(off))
    }

    pub fn va_to_offset(&self, va: u64) -> Result<u64, AddrError> {
        let r = self.region_for_va(va).ok_or(AddrError::Unmapped(va))?;
        let delta = va - r.va;
        if delta < r.file_size {
            r.offset.checked_add(delta).ok_or(AddrError::Overflow)
        } else {
            let region = self
                .section_for_va(va)
                .map(|s| s.full_name())
                .unwrap_or_else(|| r.name.clone());
            Err(AddrError::NoFileBacking { va, region })
        }
    }

    pub fn offset_to_va(&self, off: u64) -> Result<u64, AddrError> {
        let size = self.bytes().len() as u64;
        if off >= size {
            return Err(AddrError::OffsetPastEnd { off, size });
        }
        self.regions
            .iter()
            .find(|r| r.file_size > 0 && off >= r.offset && off - r.offset < r.file_size)
            .map(|r| r.va.wrapping_add(off - r.offset))
            .ok_or(AddrError::OffsetNotMapped(off))
    }

    pub fn va_to_rva(&self, va: u64) -> Result<u64, AddrError> {
        va.checked_sub(self.image_base).ok_or(AddrError::BelowBase {
            va,
            base: self.image_base,
        })
    }

    pub fn rva_to_va(&self, rva: u64) -> Result<u64, AddrError> {
        self.image_base.checked_add(rva).ok_or(AddrError::Overflow)
    }

    /// File-backed bytes of a section, clamped to the end of the file.
    pub fn section_data(&self, s: &Section) -> &[u8] {
        clamp_slice(self.bytes(), s.offset, s.file_size)
    }

    /// Up to `len` file-backed bytes starting at `va` (stops at the end of the region).
    pub fn bytes_at_va(&self, va: u64, len: u64) -> Result<&[u8], AddrError> {
        let off = self.va_to_offset(va)?;
        let r = self.region_for_va(va).ok_or(AddrError::Unmapped(va))?;
        let avail = r.file_size - (va - r.va);
        Ok(clamp_slice(self.bytes(), off, len.min(avail)))
    }

    pub fn find_section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn has_section(&self, name: &str) -> bool {
        self.find_section(name).is_some()
    }

    pub fn elf(&self) -> Option<&ElfInfo> {
        match &self.details {
            Details::Elf(e) => Some(e),
            _ => None,
        }
    }

    pub fn pe(&self) -> Option<&PeInfo> {
        match &self.details {
            Details::Pe(p) => Some(p),
            _ => None,
        }
    }

    pub fn macho(&self) -> Option<&MachoInfo> {
        match &self.details {
            Details::Macho(m) => Some(m),
            _ => None,
        }
    }
}

/// `data[off..off+len]` clamped to the slice bounds (never panics).
pub fn clamp_slice(data: &[u8], off: u64, len: u64) -> &[u8] {
    let total = data.len() as u64;
    if off >= total {
        return &[];
    }
    let end = off.saturating_add(len).min(total);
    &data[off as usize..end as usize]
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A small synthetic binary: headers + .text (file-backed) + .bss (zero-fill).
    pub fn sample() -> Binary {
        let perms_rx = Perms::new(true, false, true);
        let perms_rw = Perms::new(true, true, false);
        Binary {
            path: PathBuf::from("sample"),
            format: Format::Elf,
            kind: FileKind::Executable,
            arch: Arch::X86_64,
            bits: 64,
            endian: Endian::Little,
            thumb: false,
            os: "Linux".into(),
            abi: None,
            entry: Some(0x401000),
            image_base: 0x400000,
            file_size: 0x3000,
            sections: vec![
                Section {
                    index: 1,
                    name: ".text".into(),
                    segment: None,
                    addr: 0x401000,
                    size: 0x1000,
                    offset: 0x1000,
                    file_size: 0x1000,
                    perms: perms_rx,
                    kind: "PROGBITS".into(),
                    flags: 0,
                    alloc: true,
                    tls: false,
                },
                Section {
                    index: 2,
                    name: ".tbss".into(),
                    segment: None,
                    addr: 0x402000,
                    size: 0x10,
                    offset: 0x2000,
                    file_size: 0,
                    perms: perms_rw,
                    kind: "NOBITS".into(),
                    flags: 0,
                    alloc: true,
                    tls: true,
                },
                Section {
                    index: 3,
                    name: ".data".into(),
                    segment: None,
                    addr: 0x402000,
                    size: 0x100,
                    offset: 0x2000,
                    file_size: 0x100,
                    perms: perms_rw,
                    kind: "PROGBITS".into(),
                    flags: 0,
                    alloc: true,
                    tls: false,
                },
                Section {
                    index: 4,
                    name: ".bss".into(),
                    segment: None,
                    addr: 0x402100,
                    size: 0x800,
                    offset: 0x2100,
                    file_size: 0,
                    perms: perms_rw,
                    kind: "NOBITS".into(),
                    flags: 0,
                    alloc: true,
                    tls: false,
                },
            ],
            segments: vec![],
            regions: vec![
                Region {
                    name: "LOAD0".into(),
                    va: 0x400000,
                    vsize: 0x2000,
                    offset: 0,
                    file_size: 0x2000,
                    perms: perms_rx,
                },
                Region {
                    name: "LOAD1".into(),
                    va: 0x402000,
                    vsize: 0x900,
                    offset: 0x2000,
                    file_size: 0x100,
                    perms: perms_rw,
                },
            ],
            symbols: vec![],
            imports: vec![],
            exports: vec![],
            relocations: vec![],
            libraries: vec![],
            interpreter: None,
            details: Details::Raw(RawInfo::default()),
            warnings: vec![],
            data: Data::from_vec((0..0x3000u32).map(|i| i as u8).collect()),
        }
    }

    #[test]
    fn va_to_offset_inside_file_backed_region() {
        let b = sample();
        assert_eq!(b.va_to_offset(0x400000), Ok(0));
        assert_eq!(b.va_to_offset(0x401234), Ok(0x1234));
        assert_eq!(b.va_to_offset(0x4020ff), Ok(0x20ff));
    }

    #[test]
    fn va_in_bss_has_no_file_backing() {
        let b = sample();
        match b.va_to_offset(0x402100) {
            Err(AddrError::NoFileBacking { va, region }) => {
                assert_eq!(va, 0x402100);
                assert_eq!(region, ".bss");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn unmapped_va_is_reported() {
        let b = sample();
        assert_eq!(b.va_to_offset(0x10), Err(AddrError::Unmapped(0x10)));
        assert_eq!(b.va_to_offset(0x402900), Err(AddrError::Unmapped(0x402900)));
        assert!(b.va_to_offset(u64::MAX).is_err());
    }

    #[test]
    fn offset_to_va_round_trips() {
        let b = sample();
        for off in [0u64, 0x1000, 0x1fff, 0x2000, 0x20ff] {
            let va = b.offset_to_va(off).unwrap();
            assert_eq!(b.va_to_offset(va), Ok(off));
        }
    }

    #[test]
    fn offset_outside_regions() {
        let b = sample();
        assert_eq!(
            b.offset_to_va(0x2100),
            Err(AddrError::OffsetNotMapped(0x2100))
        );
        assert_eq!(
            b.offset_to_va(0x3000),
            Err(AddrError::OffsetPastEnd {
                off: 0x3000,
                size: 0x3000
            })
        );
    }

    #[test]
    fn rva_conversions() {
        let b = sample();
        assert_eq!(b.va_to_rva(0x401000), Ok(0x1000));
        assert_eq!(b.rva_to_va(0x1000), Ok(0x401000));
        assert!(matches!(
            b.va_to_rva(0x10),
            Err(AddrError::BelowBase { .. })
        ));
        assert_eq!(b.rva_to_va(u64::MAX), Err(AddrError::Overflow));
    }

    #[test]
    fn section_lookup_prefers_non_tls() {
        let b = sample();
        assert_eq!(b.section_for_va(0x402000).unwrap().name, ".data");
        assert_eq!(b.section_for_va(0x401500).unwrap().name, ".text");
        assert!(b.section_for_va(0x500000).is_none());
        assert_eq!(b.section_for_offset(0x1004).unwrap().name, ".text");
    }

    #[test]
    fn bytes_at_va_is_clamped_to_region() {
        let b = sample();
        assert_eq!(
            b.bytes_at_va(0x401000, 4).unwrap(),
            &[0x00, 0x01, 0x02, 0x03]
        );
        assert_eq!(b.bytes_at_va(0x4020fe, 100).unwrap().len(), 2);
    }

    #[test]
    fn arch_spec_parsing() {
        assert_eq!(ArchSpec::parse("x86_64").unwrap().arch, Arch::X86_64);
        assert_eq!(ArchSpec::parse("AMD64").unwrap().bits, 64);
        let t = ArchSpec::parse("thumb").unwrap();
        assert!(t.thumb && t.arch == Arch::Arm);
        assert_eq!(ArchSpec::parse("mips").unwrap().endian, Endian::Big);
        assert_eq!(ArchSpec::parse("mipsel").unwrap().endian, Endian::Little);
        assert!(ArchSpec::parse("z80").is_none());
    }

    #[test]
    fn perms_display() {
        assert_eq!(Perms::new(true, false, true).to_string(), "r-x");
        assert_eq!(Perms::default().to_string(), "---");
        assert!(Perms::new(true, true, true).is_rwx());
    }

    #[test]
    fn clamp_slice_never_panics() {
        let d = [1u8, 2, 3];
        assert_eq!(clamp_slice(&d, 1, 10), &[2, 3]);
        assert!(clamp_slice(&d, 5, 1).is_empty());
        assert!(clamp_slice(&d, 0, u64::MAX).len() == 3);
    }
}
