//! Symbol table view: defined symbols by address, then imports, then file symbols.

use regex::Regex;
use serde::Serialize;

use crate::model::*;

#[derive(Debug, Clone, Serialize)]
pub struct SymbolRow {
    pub addr: u64,
    pub size: u64,
    pub kind: SymKind,
    pub bind: SymBind,
    pub section: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    pub defined: bool,
    pub dynamic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub thumb: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolsReport {
    /// Symbols in the binary before filtering.
    pub total: usize,
    pub filter: Option<String>,
    pub symbols: Vec<SymbolRow>,
}

pub fn analyze(bin: &Binary, filter: Option<&Regex>) -> SymbolsReport {
    let mut rows: Vec<SymbolRow> = bin
        .symbols
        .iter()
        .filter(|s| match filter {
            Some(re) => {
                re.is_match(&s.name) || s.demangled.as_deref().is_some_and(|d| re.is_match(d))
            }
            None => true,
        })
        .map(|s| SymbolRow {
            addr: s.addr,
            size: s.size,
            kind: s.kind,
            bind: s.bind,
            section: s.section.clone(),
            name: s.name.clone(),
            demangled: s.demangled.clone(),
            defined: s.defined,
            dynamic: s.dynamic,
            version: s.version.clone(),
            library: s.library.clone(),
            thumb: s.thumb,
        })
        .collect();
    // 0: defined symbols by address, 1: undefined (imports) by name, 2: FILE symbols.
    let group = |r: &SymbolRow| match (r.kind, r.defined) {
        (SymKind::File, _) => 2,
        (_, true) => 0,
        (_, false) => 1,
    };
    rows.sort_by(|a, b| {
        group(a)
            .cmp(&group(b))
            .then_with(|| {
                if group(a) == 0 {
                    a.addr.cmp(&b.addr)
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .then_with(|| a.name.cmp(&b.name))
    });
    SymbolsReport {
        total: bin.symbols.len(),
        filter: filter.map(|r| r.as_str().to_string()),
        symbols: rows,
    }
}

// ---------------------------------------------------------------------------
// Risky APIs (shared by --imports and --auto)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    /// Unbounded copies / reads: classic memory corruption.
    Memory,
    /// Runs commands or programs.
    Exec,
    /// Writes into or runs code in other processes.
    Injection,
    /// Makes memory executable in the own process (shellcode loaders, JITs, CRTs).
    ExecMemory,
    AntiDebug,
    /// Resolves APIs at run time (common in packers and malware).
    DynamicLoad,
    Network,
    Persistence,
    Crypto,
    Privilege,
    Keylogging,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Risk::Memory => "memory-unsafe",
            Risk::Exec => "exec",
            Risk::Injection => "injection",
            Risk::ExecMemory => "exec-memory",
            Risk::AntiDebug => "anti-debug",
            Risk::DynamicLoad => "dynamic-api",
            Risk::Network => "network",
            Risk::Persistence => "persistence",
            Risk::Crypto => "crypto",
            Risk::Privilege => "privilege",
            Risk::Keylogging => "keylogging",
        }
    }

    /// Shown in red rather than yellow.
    pub fn high(self) -> bool {
        matches!(self, Risk::Memory | Risk::Exec | Risk::Injection)
    }
}

/// Classify an imported function name (`_gets`, `puts@GLIBC_2.2.5`, `CreateProcessW`).
pub fn risk(name: &str) -> Option<Risk> {
    let base = name.split('@').next().unwrap_or(name);
    let base = base.strip_prefix("__imp_").unwrap_or(base);
    let base = base.trim_start_matches('_');
    if let Some(r) = risk_exact(base) {
        return Some(r);
    }
    // Win32 A/W variants: CreateProcessW -> CreateProcess
    match base.strip_suffix('A').or_else(|| base.strip_suffix('W')) {
        Some(stem) if stem.len() > 3 => {
            risk_exact(stem).filter(|_| base.as_bytes()[0].is_ascii_uppercase())
        }
        _ => None,
    }
}

fn risk_exact(n: &str) -> Option<Risk> {
    use Risk::*;
    Some(match n {
        "gets" | "strcpy" | "strcat" | "sprintf" | "vsprintf" | "scanf" | "sscanf" | "fscanf"
        | "vscanf" | "vsscanf" | "vfscanf" | "stpcpy" | "wcscpy" | "wcscat" | "getwd"
        | "mktemp" | "tmpnam" | "lstrcpy" | "lstrcat" | "StrCpy" | "StrCat" | "wsprintf" => Memory,
        "system"
        | "execve"
        | "execv"
        | "execvp"
        | "execvpe"
        | "execl"
        | "execlp"
        | "execle"
        | "fexecve"
        | "popen"
        | "posix_spawn"
        | "posix_spawnp"
        | "wsystem"
        | "WinExec"
        | "ShellExecute"
        | "ShellExecuteEx"
        | "CreateProcess"
        | "CreateProcessAsUser"
        | "CreateProcessWithLogon"
        | "CreateProcessWithToken" => Exec,
        "VirtualAllocEx"
        | "VirtualProtectEx"
        | "WriteProcessMemory"
        | "CreateRemoteThread"
        | "CreateRemoteThreadEx"
        | "NtCreateThreadEx"
        | "RtlCreateUserThread"
        | "QueueUserAPC"
        | "NtQueueApcThread"
        | "SetThreadContext"
        | "NtSetContextThread"
        | "NtUnmapViewOfSection"
        | "ZwUnmapViewOfSection"
        | "NtWriteVirtualMemory"
        | "NtMapViewOfSection"
        | "SetWindowsHookEx"
        | "process_vm_writev" => Injection,
        "VirtualAlloc"
        | "VirtualProtect"
        | "NtAllocateVirtualMemory"
        | "NtProtectVirtualMemory"
        | "mprotect"
        | "mmap" => ExecMemory,
        "IsDebuggerPresent"
        | "CheckRemoteDebuggerPresent"
        | "NtQueryInformationProcess"
        | "OutputDebugString"
        | "NtSetInformationThread"
        | "ptrace"
        | "ZwQueryInformationProcess" => AntiDebug,
        "LoadLibrary"
        | "LoadLibraryEx"
        | "GetProcAddress"
        | "LdrLoadDll"
        | "LdrGetProcedureAddress"
        | "dlopen"
        | "dlsym" => DynamicLoad,
        "socket" | "connect" | "WSAStartup" | "WSASocket" | "InternetOpen" | "InternetOpenUrl"
        | "InternetConnect" | "HttpOpenRequest" | "HttpSendRequest" | "URLDownloadToFile"
        | "WinHttpOpen" | "WinHttpConnect" | "WinHttpSendRequest" | "getaddrinfo"
        | "gethostbyname" => Network,
        "RegSetValue"
        | "RegSetValueEx"
        | "RegCreateKey"
        | "RegCreateKeyEx"
        | "CreateService"
        | "StartService"
        | "ChangeServiceConfig" => Persistence,
        "CryptEncrypt"
        | "CryptDecrypt"
        | "CryptGenKey"
        | "CryptAcquireContext"
        | "BCryptEncrypt"
        | "BCryptDecrypt"
        | "BCryptGenerateSymmetricKey" => Crypto,
        "AdjustTokenPrivileges"
        | "OpenProcessToken"
        | "LookupPrivilegeValue"
        | "ImpersonateLoggedOnUser"
        | "DuplicateTokenEx"
        | "setuid"
        | "setreuid" => Privilege,
        "GetAsyncKeyState" | "GetKeyState" | "GetKeyboardState" => Keylogging,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// --imports / --exports
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ImportRow {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub slot: Option<u64>,
    pub plt: Option<u64>,
    pub weak: bool,
    pub delayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<Risk>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LibraryImports {
    /// `None`: the format does not record which library provides these.
    pub library: Option<String>,
    pub imports: Vec<ImportRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportsReport {
    pub total: usize,
    pub risky: usize,
    pub libraries: Vec<LibraryImports>,
}

pub fn imports(bin: &Binary) -> ImportsReport {
    let mut libraries: Vec<LibraryImports> = Vec::new();
    for imp in &bin.imports {
        let key = imp.library.clone();
        let row = ImportRow {
            name: imp.label(),
            demangled: imp.demangled.clone(),
            ordinal: imp.ordinal,
            version: imp.version.clone(),
            slot: imp.slot,
            plt: imp.plt,
            weak: imp.weak,
            delayed: imp.delayed,
            risk: imp.name.as_deref().and_then(risk),
        };
        match libraries.iter_mut().find(|l| l.library == key) {
            Some(l) => l.imports.push(row),
            None => libraries.push(LibraryImports {
                library: key,
                imports: vec![row],
            }),
        }
    }
    // Libraries in load order, but unattributed imports last.
    libraries.sort_by_key(|l| l.library.is_none());
    ImportsReport {
        total: bin.imports.len(),
        risky: libraries
            .iter()
            .flat_map(|l| &l.imports)
            .filter(|i| i.risk.is_some())
            .count(),
        libraries,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportRow {
    pub addr: u64,
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarder: Option<String>,
    pub kind: SymKind,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportsReport {
    pub total: usize,
    pub exports: Vec<ExportRow>,
}

pub fn exports(bin: &Binary) -> ExportsReport {
    let mut exports: Vec<ExportRow> = bin
        .exports
        .iter()
        .map(|e| ExportRow {
            addr: e.addr,
            name: e.name.clone(),
            demangled: e.demangled.clone(),
            ordinal: e.ordinal,
            forwarder: e.forwarder.clone(),
            kind: e.kind,
        })
        .collect();
    exports.sort_by(|a, b| {
        (a.forwarder.is_some(), a.addr, a.ordinal, &a.name).cmp(&(
            b.forwarder.is_some(),
            b.addr,
            b.ordinal,
            &b.name,
        ))
    });
    ExportsReport {
        total: exports.len(),
        exports,
    }
}

// ---------------------------------------------------------------------------
// --plt / --got
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct PltRow {
    pub addr: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    pub slot: Option<u64>,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PltReport {
    pub format: Format,
    pub entries: Vec<PltRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn plt(bin: &Binary) -> PltReport {
    let mut note = None;
    let mut entries: Vec<PltRow> = match &bin.details {
        Details::Elf(e) => e
            .plt
            .iter()
            .map(|p| PltRow {
                addr: p.addr,
                demangled: crate::loader::demangle(&p.name),
                name: p.name.clone(),
                slot: Some(p.slot),
                section: Some(p.section.clone()),
            })
            .collect(),
        Details::Macho(_) => bin
            .imports
            .iter()
            .filter_map(|i| {
                Some(PltRow {
                    addr: i.plt?,
                    name: i.label(),
                    demangled: i.demangled.clone(),
                    slot: i.slot,
                    section: bin.section_for_va(i.plt?).map(|s| s.full_name()),
                })
            })
            .collect(),
        Details::Pe(_) => {
            note =
                Some("PE images call imports through the IAT, not a PLT (see --got)".to_string());
            Vec::new()
        }
        Details::Raw(_) => Vec::new(),
    };
    if entries.is_empty() && note.is_none() {
        note = Some(match bin.format {
            Format::Elf if bin.imports.is_empty() => "no dynamic imports, so no PLT".to_string(),
            Format::Elf => {
                "no PLT stubs found (imports go through the GOT directly, e.g. -fno-plt)"
                    .to_string()
            }
            _ => "no call stubs".to_string(),
        });
    }
    entries.sort_by_key(|e| e.addr);
    PltReport {
        format: bin.format,
        entries,
        note,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GotRow {
    /// Slot address.
    pub addr: u64,
    /// Pointer stored in the file (lazy-binding stub, 0, or a prelinked value).
    pub value: Option<u64>,
    pub name: Option<String>,
    /// Relocation type (ELF) or slot kind (`IAT`, `lazy pointer`, ...).
    pub kind: String,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GotReport {
    pub format: Format,
    pub entries: Vec<GotRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

fn read_ptr(bin: &Binary, va: u64) -> Option<u64> {
    let size = if bin.bits == 32 { 4 } else { 8 };
    let raw = bin.bytes_at_va(va, size).ok()?;
    super::read_uint(raw, 0, size as usize, bin.endian)
}

pub fn got(bin: &Binary) -> GotReport {
    let section_of = |va: u64| bin.section_for_va(va).map(|s| s.full_name());
    let mut entries: Vec<GotRow> = match bin.format {
        Format::Elf => {
            let is_got = |va: u64| {
                bin.section_for_va(va)
                    .is_some_and(|s| s.name.contains("got"))
            };
            bin.relocations
                .iter()
                .filter(|r| is_got(r.addr))
                .map(|r| GotRow {
                    addr: r.addr,
                    value: read_ptr(bin, r.addr),
                    name: r.symbol.clone(),
                    kind: r.kind.trim_start_matches("R_").to_string(),
                    section: section_of(r.addr),
                })
                .collect()
        }
        Format::Pe | Format::Macho => bin
            .imports
            .iter()
            .filter_map(|i| {
                let slot = i.slot?;
                let kind = match (bin.format, i.delayed) {
                    (Format::Pe, false) => "IAT".to_string(),
                    (Format::Pe, true) => "delay-load IAT".to_string(),
                    _ => bin
                        .section_for_va(slot)
                        .map(|s| {
                            s.kind
                                .replace("_symbol_pointers", " pointer")
                                .replace('_', " ")
                        })
                        .unwrap_or_else(|| "pointer".into()),
                };
                let name = match (&i.library, bin.format) {
                    (Some(lib), Format::Pe) => format!("{lib}!{}", i.label()),
                    _ => i.label(),
                };
                Some(GotRow {
                    addr: slot,
                    value: read_ptr(bin, slot),
                    name: Some(name),
                    kind,
                    section: section_of(slot),
                })
            })
            .collect(),
        Format::Raw => Vec::new(),
    };
    entries.sort_by_key(|e| e.addr);
    entries.dedup_by_key(|e| e.addr);
    let note = entries
        .is_empty()
        .then(|| "no GOT / IAT entries".to_string());
    GotReport {
        format: bin.format,
        entries,
        note,
    }
}

// ---------------------------------------------------------------------------
// --relocs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct RelocRow {
    pub addr: u64,
    pub kind: String,
    pub symbol: Option<String>,
    pub addend: Option<i64>,
    /// Relocation table (`.rela.plt`, `.reloc`, ...).
    pub table: String,
    /// Section the patched address belongs to.
    pub section: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelocsReport {
    pub total: usize,
    pub relocations: Vec<RelocRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn relocs(bin: &Binary) -> RelocsReport {
    let relocations: Vec<RelocRow> = bin
        .relocations
        .iter()
        .map(|r| RelocRow {
            addr: r.addr,
            kind: r.kind.clone(),
            symbol: r.symbol.clone(),
            addend: r.addend,
            table: r.source.clone(),
            section: bin.section_for_va(r.addr).map(|s| s.full_name()),
        })
        .collect();
    let note = relocations.is_empty().then(|| match bin.format {
        Format::Macho => "Mach-O rebase/bind information is not decoded as relocations".to_string(),
        _ => "no relocations".to_string(),
    });
    RelocsReport {
        total: relocations.len(),
        relocations,
        note,
    }
}

/// Build the `--symbols` regex with smart case: case-insensitive unless the
/// pattern contains an upper-case letter.
pub fn build_filter(pattern: &str) -> Result<Regex, regex::Error> {
    let insensitive = !pattern.chars().any(char::is_uppercase);
    regex::RegexBuilder::new(pattern)
        .case_insensitive(insensitive)
        .size_limit(1 << 22)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_classification() {
        assert_eq!(risk("gets"), Some(Risk::Memory));
        assert_eq!(risk("gets@GLIBC_2.2.5"), Some(Risk::Memory));
        assert_eq!(risk("_strcpy"), Some(Risk::Memory), "Mach-O underscore");
        assert_eq!(risk("system"), Some(Risk::Exec));
        assert_eq!(risk("CreateProcessW"), Some(Risk::Exec));
        assert_eq!(risk("ShellExecuteExA"), Some(Risk::Exec));
        assert_eq!(risk("WriteProcessMemory"), Some(Risk::Injection));
        assert_eq!(risk("VirtualAlloc"), Some(Risk::ExecMemory));
        assert_eq!(risk("IsDebuggerPresent"), Some(Risk::AntiDebug));
        assert_eq!(risk("GetProcAddress"), Some(Risk::DynamicLoad));
        assert_eq!(risk("LoadLibraryExW"), Some(Risk::DynamicLoad));
        assert_eq!(risk("RegSetValueExW"), Some(Risk::Persistence));
        assert_eq!(risk("puts"), None);
        assert_eq!(risk("getsA"), None, "A/W stripping only for Win32 names");
        assert_eq!(risk("printf"), None);
        assert!(Risk::Exec.high() && !Risk::Network.high());
    }

    #[test]
    fn smart_case_filter() {
        let re = build_filter("win").unwrap();
        assert!(re.is_match("Win"));
        let re = build_filter("Win").unwrap();
        assert!(!re.is_match("win"));
        assert!(build_filter("(").is_err());
    }
}
