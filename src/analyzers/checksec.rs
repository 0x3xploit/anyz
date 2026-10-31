//! Exploit-mitigation checks (checksec / winchecksec style) for ELF, PE and Mach-O.

use std::collections::HashSet;

use serde::Serialize;

use super::c_name;
use crate::model::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Enabled,
    Partial,
    Disabled,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize)]
pub struct Mitigation {
    pub name: &'static str,
    pub status: Status,
    /// Short value such as `full`, `partial`, `yes`, `no`, `DSO`.
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Mitigation {
    fn new(name: &'static str, status: Status, value: &str) -> Self {
        Mitigation {
            name,
            status,
            value: value.to_string(),
            detail: None,
        }
    }
    fn on(name: &'static str, value: &str) -> Self {
        Self::new(name, Status::Enabled, value)
    }
    fn off(name: &'static str, value: &str) -> Self {
        Self::new(name, Status::Disabled, value)
    }
    fn partial(name: &'static str, value: &str) -> Self {
        Self::new(name, Status::Partial, value)
    }
    fn na(name: &'static str) -> Self {
        Self::new(name, Status::NotApplicable, "n/a")
    }
    fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
}

/// Whether a property helps the defender (`good`), makes the binary easier to
/// attack or reverse (`bad`), or neither (`neutral`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Good,
    Bad,
    Neutral,
}

/// A hardening-related fact that is not itself a mitigation: RPATH, TEXTREL,
/// stripped symbols, relocations, managed code.
#[derive(Debug, Clone, Serialize)]
pub struct Property {
    pub name: &'static str,
    pub value: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Property {
    fn new(name: &'static str, verdict: Verdict, value: &str) -> Self {
        Property {
            name,
            value: value.to_string(),
            verdict,
            detail: None,
        }
    }
    fn good(name: &'static str, value: &str) -> Self {
        Self::new(name, Verdict::Good, value)
    }
    fn bad(name: &'static str, value: &str) -> Self {
        Self::new(name, Verdict::Bad, value)
    }
    fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChecksecReport {
    pub format: Format,
    pub items: Vec<Mitigation>,
    /// Extra hardening facts shown by `--checksec` but not in the info panel.
    pub extra: Vec<Property>,
}

pub fn analyze(bin: &Binary) -> ChecksecReport {
    let items = match &bin.details {
        Details::Elf(e) => elf(bin, e),
        Details::Pe(p) => pe(bin, p),
        Details::Macho(m) => macho(bin, m),
        Details::Raw(_) => Vec::new(),
    };
    ChecksecReport {
        format: bin.format,
        items,
        extra: extra(bin),
    }
}

fn extra(bin: &Binary) -> Vec<Property> {
    let mut v = Vec::new();
    match &bin.details {
        Details::Elf(e) => {
            for (name, paths) in [("RPATH", &e.rpath), ("RUNPATH", &e.runpath)] {
                v.push(if paths.is_empty() {
                    Property::good(name, "none")
                } else {
                    Property::bad(name, "set").detail(format!(
                        "{}: libraries can be loaded from here (hijack risk if writable)",
                        paths.join(":")
                    ))
                });
            }
            v.push(if e.textrel {
                Property::bad("TEXTREL", "yes").detail("code is patched at load time")
            } else {
                Property::good("TEXTREL", "no")
            });
            v.push(if e.has_symtab {
                Property::bad("Stripped", "no").detail("symbol table present (easier to reverse)")
            } else {
                Property::good("Stripped", "yes")
            });
        }
        Details::Pe(p) => {
            v.push(if p.characteristics & 0x0001 != 0 {
                Property::bad("Relocations", "stripped").detail("image cannot be relocated")
            } else {
                Property::good("Relocations", "present")
            });
            v.push(match &p.clr {
                Some(_) => Property::new("Managed (.NET)", Verdict::Neutral, "yes")
                    .detail("native mitigations mostly don't apply to IL code"),
                None => Property::new("Managed (.NET)", Verdict::Neutral, "no"),
            });
        }
        Details::Macho(m) => {
            if !m.rpaths.is_empty() {
                v.push(Property::bad("RPATH", "set").detail(m.rpaths.join(", ")));
            }
        }
        Details::Raw(_) => {}
    }
    v
}

/// Names of everything the binary imports or defines, without the Mach-O `_` prefix.
fn all_names(bin: &Binary) -> HashSet<&str> {
    let macho = bin.format == Format::Macho;
    bin.imports
        .iter()
        .filter_map(|i| i.name.as_deref())
        .chain(
            bin.symbols
                .iter()
                .map(|s| s.name.split('@').next().unwrap_or(&s.name)),
        )
        .map(|n| c_name(n, macho))
        .collect()
}

fn import_names(bin: &Binary) -> HashSet<&str> {
    let macho = bin.format == Format::Macho;
    bin.imports
        .iter()
        .filter_map(|i| i.name.as_deref())
        .map(|n| c_name(n, macho))
        .collect()
}

const CANARY_SYMBOLS: &[&str] = &[
    "__stack_chk_fail",
    "__stack_chk_guard",
    "__stack_chk_fail_local",
    "__intel_security_cookie",
];

/// libc functions that have `__*_chk` fortified variants.
const FORTIFIABLE: &[&str] = &[
    "memcpy",
    "memmove",
    "mempcpy",
    "memset",
    "stpcpy",
    "stpncpy",
    "strcat",
    "strcpy",
    "strncat",
    "strncpy",
    "sprintf",
    "snprintf",
    "vsprintf",
    "vsnprintf",
    "printf",
    "fprintf",
    "vprintf",
    "vfprintf",
    "dprintf",
    "vdprintf",
    "asprintf",
    "vasprintf",
    "gets",
    "fgets",
    "fgets_unlocked",
    "fread",
    "fread_unlocked",
    "read",
    "pread",
    "pread64",
    "recv",
    "recvfrom",
    "readlink",
    "readlinkat",
    "getcwd",
    "getwd",
    "realpath",
    "wcscpy",
    "wcsncpy",
    "wcscat",
    "wcsncat",
    "wmemcpy",
    "wmemmove",
    "wmemset",
    "wcpcpy",
    "wcpncpy",
    "swprintf",
    "wprintf",
    "fwprintf",
    "vswprintf",
    "vwprintf",
    "vfwprintf",
    "mbstowcs",
    "wcstombs",
    "wcrtomb",
    "wctomb",
    "mbsrtowcs",
    "wcsrtombs",
    "confstr",
    "getgroups",
    "ttyname_r",
    "getlogin_r",
    "gethostname",
    "getdomainname",
    "syslog",
    "vsyslog",
    "longjmp",
    "poll",
    "ppoll",
    "explicit_bzero",
    "obstack_printf",
    "obstack_vprintf",
    "strlen",
    "strchr",
    "strrchr",
];

fn is_fortified_name(n: &str) -> bool {
    n.starts_with("__") && n.ends_with("_chk") && n.len() > 6
}

fn has_canary(names: &HashSet<&str>) -> bool {
    CANARY_SYMBOLS.iter().any(|c| names.contains(c))
}

fn fortify(bin: &Binary) -> Mitigation {
    // Static binaries carry libc's own *_chk implementations, so only trust imports
    // when the binary is dynamically linked.
    let pool = if bin.imports.is_empty() {
        all_names(bin)
    } else {
        import_names(bin)
    };
    let fortified = pool.iter().filter(|n| is_fortified_name(n)).count();
    let fortifiable = FORTIFIABLE
        .iter()
        .filter(|f| pool.contains(**f) || pool.contains(format!("__{f}_chk").as_str()))
        .count();
    if fortified > 0 {
        Mitigation::on("FORTIFY", "yes")
            .detail(format!("{fortified} fortified, {fortifiable} fortifiable"))
    } else if fortifiable > 0 {
        Mitigation::off("FORTIFY", "no").detail(format!("0 fortified, {fortifiable} fortifiable"))
    } else {
        Mitigation::na("FORTIFY").detail("no fortifiable libc calls")
    }
}

fn elf(bin: &Binary, e: &ElfInfo) -> Vec<Mitigation> {
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    let obj = matches!(bin.kind, FileKind::Object | FileKind::Core);
    let mut v = Vec::new();

    v.push(match e.e_type {
        _ if obj => Mitigation::na("NX"),
        _ => match e.gnu_stack {
            Some(p) if p.x => Mitigation::off("NX", "no").detail("PT_GNU_STACK is executable"),
            Some(_) => Mitigation::on("NX", "yes"),
            None => Mitigation::off("NX", "no")
                .detail("no PT_GNU_STACK; the stack defaults to executable"),
        },
    });

    v.push(match e.e_type {
        ET_EXEC => {
            Mitigation::off("PIE", "no").detail(format!("fixed load address {:#x}", bin.image_base))
        }
        ET_DYN if bin.kind == FileKind::SharedLibrary => {
            Mitigation::on("PIE", "DSO").detail("shared object (position independent)")
        }
        ET_DYN => Mitigation::on("PIE", "yes"),
        _ => Mitigation::na("PIE"),
    });

    v.push(if obj {
        Mitigation::na("RELRO")
    } else if e.gnu_relro && e.bind_now {
        Mitigation::on("RELRO", "full")
    } else if e.gnu_relro {
        Mitigation::partial("RELRO", "partial").detail("GOT stays writable (lazy binding)")
    } else {
        Mitigation::off("RELRO", "none")
    });

    let names = all_names(bin);
    v.push(if has_canary(&names) {
        Mitigation::on("Canary", "yes")
    } else {
        Mitigation::off("Canary", "no")
    });

    v.push(fortify(bin));

    let wx: Vec<String> = bin
        .segments
        .iter()
        .filter(|s| s.loadable && s.perms.is_wx())
        .map(|s| format!("{}[{}] {}", s.name, s.index, s.perms))
        .collect();
    v.push(if obj {
        Mitigation::na("W^X")
    } else if wx.is_empty() {
        Mitigation::on("W^X", "yes")
    } else {
        Mitigation::off("W^X", "RWX").detail(format!("writable+executable: {}", wx.join(", ")))
    });

    if let Some(f) = e.x86_features {
        if f & 1 != 0 {
            v.push(Mitigation::on("IBT", "yes").detail("CET indirect branch tracking"));
        }
        if f & 2 != 0 {
            v.push(Mitigation::on("SHSTK", "yes").detail("CET shadow stack"));
        }
    }
    if let Some(f) = e.aarch64_features {
        if f & 1 != 0 {
            v.push(Mitigation::on("BTI", "yes").detail("branch target identification"));
        }
        if f & 2 != 0 {
            v.push(Mitigation::on("PAC", "yes").detail("pointer authentication"));
        }
    }
    v
}

fn pe(bin: &Binary, p: &PeInfo) -> Vec<Mitigation> {
    const NX_COMPAT: u16 = 0x0100;
    const DYNAMIC_BASE: u16 = 0x0040;
    const HIGH_ENTROPY_VA: u16 = 0x0020;
    const FORCE_INTEGRITY: u16 = 0x0080;
    const NO_SEH: u16 = 0x0400;
    const APPCONTAINER: u16 = 0x1000;
    const GUARD_CF: u16 = 0x4000;
    const RELOCS_STRIPPED: u16 = 0x0001;
    const GUARD_CF_INSTRUMENTED: u32 = 0x100;

    let dc = p.dll_characteristics;
    let mut v = Vec::new();

    v.push(if dc & NX_COMPAT != 0 {
        Mitigation::on("DEP", "yes")
    } else if p.pe32_plus {
        Mitigation::on("DEP", "forced")
            .detail("NX_COMPAT not set, but DEP is always on for 64-bit processes")
    } else {
        Mitigation::off("DEP", "no")
    });

    v.push(if dc & DYNAMIC_BASE == 0 {
        Mitigation::off("ASLR", "no").detail(format!("fixed image base {:#x}", bin.image_base))
    } else if p.characteristics & RELOCS_STRIPPED != 0 {
        Mitigation::partial("ASLR", "partial")
            .detail("DYNAMIC_BASE set but relocations are stripped")
    } else {
        Mitigation::on("ASLR", "yes")
    });

    v.push(if !p.pe32_plus {
        Mitigation::na("High-entropy VA").detail("32-bit image")
    } else if dc & HIGH_ENTROPY_VA != 0 && dc & DYNAMIC_BASE != 0 {
        Mitigation::on("High-entropy VA", "yes")
    } else {
        Mitigation::off("High-entropy VA", "no")
    });

    let instrumented = p
        .load_config
        .as_ref()
        .is_some_and(|l| l.guard_flags & GUARD_CF_INSTRUMENTED != 0);
    v.push(match (dc & GUARD_CF != 0, instrumented) {
        (true, true) => {
            let n = p
                .load_config
                .as_ref()
                .map_or(0, |l| l.guard_cf_function_count);
            Mitigation::on("CFG", "yes").detail(format!("{n} guarded call targets"))
        }
        (true, false) => Mitigation::partial("CFG", "flag only")
            .detail("GUARD_CF set but the image is not instrumented"),
        (false, _) => Mitigation::off("CFG", "no"),
    });

    v.push(if bin.arch != Arch::X86 {
        Mitigation::na("SafeSEH").detail("table-based exception handling on this architecture")
    } else if dc & NO_SEH != 0 {
        Mitigation::on("SafeSEH", "no SEH").detail("image has no SEH handlers")
    } else {
        match &p.load_config {
            Some(l) if l.se_handler_count > 0 && l.se_handler_table != 0 => {
                Mitigation::on("SafeSEH", "yes")
                    .detail(format!("{} registered handlers", l.se_handler_count))
            }
            _ => Mitigation::off("SafeSEH", "no"),
        }
    });

    let names = import_names(bin);
    v.push(match &p.load_config {
        Some(l) if l.security_cookie != 0 => {
            Mitigation::on("GS", "yes").detail(match p.gs_functions {
                Some(n) => format!("/GS security cookie, {n} protected functions"),
                None => "/GS security cookie".to_string(),
            })
        }
        _ if has_canary(&names) || has_canary(&all_names(bin)) => {
            Mitigation::on("GS", "canary").detail("GCC stack protector (__stack_chk_fail)")
        }
        _ => Mitigation::off("GS", "no"),
    });

    v.push(match &p.signature {
        Some(s) => Mitigation::on("Signed", "yes").detail(format!(
            "Authenticode, {} certificate(s), not verified",
            s.certificates
        )),
        None => Mitigation::off("Signed", "no"),
    });

    let wx: Vec<&str> = bin
        .sections
        .iter()
        .filter(|s| s.perms.is_wx())
        .map(|s| s.name.as_str())
        .collect();
    v.push(if wx.is_empty() {
        Mitigation::on("W^X", "yes")
    } else {
        Mitigation::off("W^X", "RWX")
            .detail(format!("writable+executable sections: {}", wx.join(", ")))
    });

    if dc & FORCE_INTEGRITY != 0 {
        v.push(Mitigation::on("Force integrity", "yes"));
    }
    if dc & APPCONTAINER != 0 {
        v.push(Mitigation::on("AppContainer", "yes"));
    }
    if p.ex_dll_characteristics.is_some_and(|x| x & 1 != 0) {
        v.push(Mitigation::on("CET", "compatible").detail("CET shadow stack compatible"));
    }
    v
}

fn macho(bin: &Binary, m: &MachoInfo) -> Vec<Mitigation> {
    const MH_PIE: u32 = 0x0020_0000;
    const MH_ALLOW_STACK_EXECUTION: u32 = 0x0002_0000;
    const CS_ADHOC: u32 = 0x2;
    const CS_RUNTIME: u32 = 0x1_0000;
    let obj = m.filetype == 1;
    let mut v = Vec::new();

    v.push(match m.filetype {
        2 if m.flags & MH_PIE != 0 => Mitigation::on("PIE", "yes"),
        2 => {
            Mitigation::off("PIE", "no").detail(format!("fixed load address {:#x}", bin.image_base))
        }
        6 | 8 => Mitigation::on("PIE", "PIC").detail("dylib/bundle (position independent)"),
        _ => Mitigation::na("PIE"),
    });

    v.push(match &m.code_signature {
        _ if obj => Mitigation::na("Code signature"),
        Some(cs) => {
            let who = cs.identifier.as_deref().map(|i| match &cs.team_id {
                Some(t) => format!("{i} (team {t})"),
                None => i.to_string(),
            });
            let adhoc = cs.flags.is_some_and(|f| f & CS_ADHOC != 0);
            let m = if cs.has_cms && !adhoc {
                Mitigation::on("Code signature", "signed")
            } else if adhoc || cs.flags.is_some() {
                Mitigation::on("Code signature", "ad-hoc")
            } else {
                Mitigation::on("Code signature", "yes")
            };
            match who {
                Some(w) => m.detail(w),
                None => m,
            }
        }
        None => Mitigation::off("Code signature", "no"),
    });

    let names = all_names(bin);
    v.push(if obj {
        Mitigation::na("Canary")
    } else if has_canary(&names) {
        Mitigation::on("Canary", "yes")
    } else {
        Mitigation::off("Canary", "no")
    });

    v.push(if obj {
        Mitigation::na("NX stack")
    } else if m.flags & MH_ALLOW_STACK_EXECUTION != 0 {
        Mitigation::off("NX stack", "no").detail("MH_ALLOW_STACK_EXECUTION is set")
    } else {
        Mitigation::on("NX stack", "yes")
    });

    let wx: Vec<&str> = bin
        .segments
        .iter()
        .filter(|s| s.perms.is_wx())
        .map(|s| s.name.as_str())
        .collect();
    v.push(if obj {
        Mitigation::na("W^X")
    } else if wx.is_empty() {
        Mitigation::on("W^X", "yes")
    } else {
        Mitigation::off("W^X", "RWX")
            .detail(format!("writable+executable segments: {}", wx.join(", ")))
    });

    let imports = import_names(bin);
    if imports.iter().any(|n| n.starts_with("objc_")) {
        v.push(
            if imports.contains("objc_release") || imports.contains("objc_storeStrong") {
                Mitigation::on("ARC", "yes")
            } else {
                Mitigation::off("ARC", "no")
            },
        );
    }
    if let Some(cs) = &m.code_signature
        && let Some(f) = cs.flags
    {
        v.push(if f & CS_RUNTIME != 0 {
            Mitigation::on("Hardened runtime", "yes")
        } else {
            Mitigation::off("Hardened runtime", "no")
        });
    }
    if let Some(enc) = &m.encryption {
        v.push(if enc.cryptid != 0 {
            Mitigation::on("Encrypted", "yes").detail("LC_ENCRYPTION_INFO cryptid != 0 (FairPlay)")
        } else {
            Mitigation::off("Encrypted", "no")
        });
    }
    if bin.segments.iter().any(|s| s.name == "__RESTRICT") {
        v.push(
            Mitigation::on("Restrict", "yes").detail("__RESTRICT segment blocks DYLD_* variables"),
        );
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fortified_names() {
        assert!(is_fortified_name("__printf_chk"));
        assert!(is_fortified_name("__memcpy_chk"));
        assert!(!is_fortified_name("__stack_chk_fail"));
        assert!(!is_fortified_name("__chk"));
        assert!(!is_fortified_name("printf"));
    }
}
