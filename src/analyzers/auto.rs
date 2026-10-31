//! `--auto`: run the relevant analyzers, then turn what they found into ranked
//! findings for CTF players (exploitation hints) and malware analysts (capabilities).

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use super::checksec::{self, Status};
use super::entropy;
use super::info;
use super::strings::{ascii_runs, utf16_runs};
use super::symbols::{Risk, risk};
use super::{Names, c_name};
use crate::model::{Binary, Details, FileKind, Format, SymKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Warn,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Ctf,
    Malware,
    General,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutoReport {
    pub high: usize,
    pub warn: usize,
    pub info: usize,
    pub findings: Vec<Finding>,
}

const MAX_EVIDENCE: usize = 6;
const MAX_STRINGS: usize = 400_000;

#[derive(Default)]
struct Findings(Vec<Finding>);

impl Findings {
    fn add(
        &mut self,
        severity: Severity,
        category: Category,
        title: impl Into<String>,
        evidence: Vec<String>,
    ) {
        let mut evidence = evidence;
        if evidence.len() > MAX_EVIDENCE {
            let more = evidence.len() - MAX_EVIDENCE;
            evidence.truncate(MAX_EVIDENCE);
            evidence.push(format!("... and {more} more"));
        }
        self.0.push(Finding {
            severity,
            category,
            title: title.into(),
            evidence,
        });
    }
}

/// A string found in the file, with where it lives.
struct Str {
    place: String,
    text: String,
}

/// Toolchain metadata (compiler banners, debug info, notes): strings there say
/// nothing about what the program does.
fn metadata_section(name: &str) -> bool {
    name == ".comment"
        || name.starts_with(".note")
        || name.starts_with(".debug")
        || name.starts_with(".zdebug")
        || name.starts_with(".gnu_debug")
        || name.starts_with("__DWARF")
        || name.starts_with('/')
}

fn collect_strings(bin: &Binary) -> Vec<Str> {
    let data = bin.bytes();
    let keep = |off: usize| {
        !bin.section_for_offset(off as u64)
            .is_some_and(|s| metadata_section(&s.full_name()))
    };
    let place = |off: usize| match bin.offset_to_va(off as u64) {
        Ok(va) => format!("{va:#x}"),
        Err(_) => format!("off:{off:#x}"),
    };
    let mut out: Vec<Str> = ascii_runs(data, 5)
        .into_iter()
        .filter(|&(s, _)| keep(s))
        .take(MAX_STRINGS)
        .map(|(s, e)| Str {
            place: place(s),
            text: data[s..e].iter().map(|&b| char::from(b)).collect(),
        })
        .collect();
    out.extend(
        utf16_runs(data, 5)
            .into_iter()
            .filter(|&(s, _)| keep(s))
            .take(MAX_STRINGS)
            .map(|(s, e)| Str {
                place: place(s),
                text: data[s..e]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| char::from(c[0]))
                    .collect(),
            }),
    );
    out
}

static URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:https?|ftp)://[a-z0-9][a-z0-9.\-]*[a-z0-9](?::\d+)?(?:/[^\s\x22'<>]*)?")
        .expect("regex")
});
static IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{2,5})?\b")
        .expect("regex")
});
static FLAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z][A-Za-z0-9_]{1,15}\{[^\s{}]{3,80}\}").expect("regex"));
static WIN_FN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(win|win_?func(tion)?|ret2win|flag|get_?flag|print_?flag|read_?flag|show_?flag|give_?shell|get_?shell|spawn_?shell|shell|backdoor|secret|super_?secret|hidden|admin|debug)$")
        .expect("regex")
});

/// (needle, case-insensitive, severity, category, title)
const STRING_RULES: &[(&str, bool, Severity, Category, &str)] = &[
    (
        "currentversion\\run",
        true,
        Severity::High,
        Category::Malware,
        "autorun registry key (persistence)",
    ),
    (
        "vssadmin delete shadows",
        true,
        Severity::High,
        Category::Malware,
        "deletes volume shadow copies (ransomware)",
    ),
    (
        "wbadmin delete",
        true,
        Severity::High,
        Category::Malware,
        "deletes backups (ransomware)",
    ),
    (
        "bcdedit /set",
        true,
        Severity::Warn,
        Category::Malware,
        "boot configuration tampering",
    ),
    (
        "schtasks",
        true,
        Severity::Warn,
        Category::Malware,
        "scheduled task creation (persistence)",
    ),
    (
        "powershell",
        true,
        Severity::Warn,
        Category::Malware,
        "PowerShell invocation",
    ),
    (
        "-encodedcommand",
        true,
        Severity::High,
        Category::Malware,
        "encoded PowerShell command",
    ),
    (
        "cmd.exe /c",
        true,
        Severity::Warn,
        Category::Malware,
        "shell command execution",
    ),
    (
        "certutil -urlcache",
        true,
        Severity::High,
        Category::Malware,
        "certutil download (living off the land)",
    ),
    (
        "bitsadmin /transfer",
        true,
        Severity::High,
        Category::Malware,
        "bitsadmin download",
    ),
    (
        "mshta",
        true,
        Severity::Warn,
        Category::Malware,
        "mshta script execution",
    ),
    (
        "rundll32",
        true,
        Severity::Info,
        Category::Malware,
        "rundll32 usage",
    ),
    (
        "/dev/tcp/",
        false,
        Severity::High,
        Category::Malware,
        "bash /dev/tcp reverse shell",
    ),
    (
        "/etc/ld.so.preload",
        false,
        Severity::High,
        Category::Malware,
        "ld.so.preload (userland rootkit)",
    ),
    (
        "ld_preload",
        true,
        Severity::Warn,
        Category::Malware,
        "LD_PRELOAD manipulation",
    ),
    (
        "dyld_insert_libraries",
        true,
        Severity::Warn,
        Category::Malware,
        "DYLD_INSERT_LIBRARIES injection",
    ),
    (
        "/etc/shadow",
        false,
        Severity::Warn,
        Category::Malware,
        "reads /etc/shadow",
    ),
    (
        "/proc/self/exe",
        false,
        Severity::Info,
        Category::Malware,
        "inspects its own executable",
    ),
    (
        "sedebugprivilege",
        true,
        Severity::Warn,
        Category::Malware,
        "requests SeDebugPrivilege",
    ),
    (
        "\\\\.\\physicaldrive",
        true,
        Severity::High,
        Category::Malware,
        "raw disk access",
    ),
    (
        "vmware",
        true,
        Severity::Warn,
        Category::Malware,
        "virtual machine detection strings",
    ),
    (
        "virtualbox",
        true,
        Severity::Warn,
        Category::Malware,
        "virtual machine detection strings",
    ),
    (
        "vboxservice",
        true,
        Severity::Warn,
        Category::Malware,
        "virtual machine detection strings",
    ),
    (
        "sbiedll.dll",
        true,
        Severity::Warn,
        Category::Malware,
        "sandbox (Sandboxie) detection",
    ),
    (
        "wireshark",
        true,
        Severity::Info,
        Category::Malware,
        "analysis-tool detection strings",
    ),
    (
        "x64dbg",
        true,
        Severity::Info,
        Category::Malware,
        "analysis-tool detection strings",
    ),
];

const STD_PE_SECTIONS: &[&str] = &[
    ".text", ".data", ".rdata", ".idata", ".edata", ".pdata", ".xdata", ".reloc", ".rsrc", ".tls",
    ".bss", ".CRT", ".gfids", ".giats", ".00cfg", ".didat", ".retplne", ".voltbl", ".fptable",
    "_RDATA", ".gehcont", ".textbss", ".msvcjmc", ".buildid", ".debug", ".ndata", "INIT", "PAGE",
    ".orpc", ".sdata", ".sbss",
];

pub fn analyze(bin: &Binary) -> AutoReport {
    let mut f = Findings::default();
    let names = Names::new(bin);
    let checks = checksec::analyze(bin);
    let status = |name: &str| {
        checks
            .items
            .iter()
            .find(|m| m.name == name)
            .map(|m| (m.status, m.value.clone()))
    };
    let macho = bin.format == Format::Macho;
    let strings = collect_strings(bin);
    let is_exec = matches!(bin.kind, FileKind::Executable);

    // ---- imports by risk ---------------------------------------------------
    let mut by_risk: Vec<(Risk, BTreeSet<String>)> = Vec::new();
    // Statically linked: libc functions are defined in the binary, not imported.
    let static_fns: Vec<&str> = if bin.imports.is_empty() {
        bin.symbols
            .iter()
            .filter(|s| s.defined && s.kind == SymKind::Func)
            .map(|s| s.name.as_str())
            .collect()
    } else {
        Vec::new()
    };
    let api_names = bin
        .imports
        .iter()
        .filter_map(|i| i.name.as_deref())
        .chain(static_fns.iter().copied());
    for name in api_names {
        if let Some(r) = risk(name) {
            let clean = c_name(name.split('@').next().unwrap_or(name), macho).to_string();
            match by_risk.iter_mut().find(|(k, _)| *k == r) {
                Some((_, set)) => {
                    set.insert(clean);
                }
                None => by_risk.push((r, BTreeSet::from([clean]))),
            }
        }
    }
    let risky = |r: Risk| -> Vec<String> {
        by_risk
            .iter()
            .find(|(k, _)| *k == r)
            .map(|(_, s)| s.iter().cloned().collect())
            .unwrap_or_default()
    };
    let imported = |n: &str| {
        bin.imports.iter().any(|i| {
            i.name
                .as_deref()
                .is_some_and(|x| c_name(x.split('@').next().unwrap_or(x), macho) == n)
        }) || static_fns.iter().any(|x| c_name(x, macho) == n)
    };

    // ---- CTF ---------------------------------------------------------------
    let win_fns: Vec<(String, u64)> = bin
        .symbols
        .iter()
        .filter(|s| s.defined && s.kind == SymKind::Func && WIN_FN.is_match(c_name(&s.name, macho)))
        .map(|s| (s.display_name().to_string(), s.addr))
        .collect();
    if !win_fns.is_empty() {
        f.add(
            Severity::Warn,
            Category::Ctf,
            "interesting function names (win/flag/shell/backdoor)",
            win_fns
                .iter()
                .map(|(n, a)| format!("{n} @ {a:#x}"))
                .collect(),
        );
    }
    let shells: Vec<String> = strings
        .iter()
        .filter(|s| {
            matches!(
                s.text.as_str(),
                "/bin/sh" | "/bin//sh" | "/bin/bash" | "/bin/zsh" | "sh -c" | "/bin/busybox"
            )
        })
        .map(|s| format!("{}: {}", s.place, s.text))
        .collect();
    if !shells.is_empty() {
        f.add(
            Severity::Warn,
            Category::Ctf,
            "shell path strings",
            shells.clone(),
        );
    }
    let memory = risky(Risk::Memory);
    if !memory.is_empty() {
        let sev = if memory.iter().any(|n| n == "gets") {
            Severity::High
        } else {
            Severity::Warn
        };
        f.add(
            sev,
            Category::Ctf,
            "memory-unsafe libc calls (unbounded copies/reads: buffer overflow candidates)",
            memory,
        );
    }
    let exec = risky(Risk::Exec);
    if !exec.is_empty() {
        if !shells.is_empty() && exec.iter().any(|e| e == "system") {
            f.add(
                Severity::High,
                Category::Ctf,
                "system() and a shell string are both present: ret2system needs no libc leak",
                vec![],
            );
        }
        let cat = if bin.format == Format::Pe {
            Category::Malware
        } else {
            Category::Ctf
        };
        f.add(Severity::Warn, cat, "command execution imports", exec);
    }
    let canary = status("Canary").or_else(|| status("GS"));
    let pie = status("PIE").or_else(|| status("ASLR"));
    let no_canary = canary.as_ref().is_some_and(|c| c.0 == Status::Disabled);
    let no_pie = pie.as_ref().is_some_and(|p| p.0 == Status::Disabled);
    if is_exec && bin.format != Format::Pe {
        if no_canary && no_pie {
            let mut ev = vec![
                "no stack canary".to_string(),
                format!("fixed load address {:#x}", bin.image_base),
            ];
            ev.extend(
                win_fns
                    .iter()
                    .map(|(n, a)| format!("ret2win target: {n} @ {a:#x}")),
            );
            let title = if win_fns.is_empty() {
                "ret2libc / ROP candidate: no canary and no PIE"
            } else {
                "ret2win candidate: no canary, no PIE and a win-like function"
            };
            f.add(Severity::High, Category::Ctf, title, ev);
        } else if no_canary {
            f.add(
                Severity::Warn,
                Category::Ctf,
                "no stack canary: overflows reach the return address (PIE needs a leak first)",
                vec![],
            );
        }
        if matches!(
            status("RELRO"),
            Some((Status::Partial | Status::Disabled, _))
        ) && !bin.imports.is_empty()
        {
            let v = status("RELRO").map(|s| s.1).unwrap_or_default();
            f.add(
                Severity::Warn,
                Category::Ctf,
                format!("GOT is writable (RELRO {v}): GOT overwrite possible"),
                vec![],
            );
        }
        if bin.imports.is_empty() && bin.format == Format::Elf && no_pie {
            f.add(
                Severity::Info,
                Category::Ctf,
                "static binary at a fixed address: plenty of ROP gadgets (ret2syscall, --gadgets)",
                vec![],
            );
        }
        let printf: Vec<String> = [
            "printf", "fprintf", "sprintf", "snprintf", "dprintf", "vprintf", "syslog",
        ]
        .iter()
        .filter(|n| imported(n))
        .map(|n| n.to_string())
        .collect();
        if !printf.is_empty() && matches!(status("FORTIFY"), Some((Status::Disabled, _))) {
            f.add(
                Severity::Info,
                Category::Ctf,
                "printf-family calls without FORTIFY: check for format-string bugs",
                printf,
            );
        }
        if ["seccomp_init", "seccomp_load", "seccomp_rule_add"]
            .iter()
            .any(|n| imported(n))
        {
            f.add(
                Severity::Info,
                Category::Ctf,
                "seccomp filter installed: some syscalls (execve?) may be blocked",
                vec![],
            );
        }
    }
    if matches!(status("NX"), Some((Status::Disabled, _)))
        || matches!(status("DEP"), Some((Status::Disabled, _)))
    {
        f.add(
            Severity::High,
            Category::Ctf,
            "executable stack / no DEP: injected shellcode can run",
            vec![],
        );
    }
    let flags: Vec<String> = strings
        .iter()
        .filter_map(|s| {
            FLAG.find(&s.text)
                .map(|m| format!("{}: {}", s.place, m.as_str()))
        })
        .filter(|e| !e.contains("${") && !e.contains("%{"))
        .take(20)
        .collect();
    if !flags.is_empty() {
        f.add(
            Severity::Info,
            Category::Ctf,
            "flag-like strings (may be decoys)",
            flags,
        );
    }

    // ---- malware capabilities --------------------------------------------------
    let inj = risky(Risk::Injection);
    if !inj.is_empty() {
        f.add(
            Severity::High,
            Category::Malware,
            "process injection APIs",
            inj,
        );
    }
    let em = risky(Risk::ExecMemory);
    if !em.is_empty() && bin.format != Format::Elf {
        f.add(
            Severity::Info,
            Category::Malware,
            "allocates or re-protects executable memory",
            em,
        );
    }
    let anti = risky(Risk::AntiDebug);
    if !anti.is_empty() {
        f.add(
            Severity::Warn,
            Category::Malware,
            "anti-debugging APIs",
            anti,
        );
    }
    let dynl = risky(Risk::DynamicLoad);
    let resolves =
        imported("GetProcAddress") || imported("dlsym") || imported("LdrGetProcedureAddress");
    if resolves && bin.imports.len() < 20 {
        f.add(
            Severity::Warn,
            Category::Malware,
            format!(
                "only {} imports plus run-time API resolution: likely packed or obfuscated",
                bin.imports.len()
            ),
            dynl,
        );
    } else if !dynl.is_empty() && bin.format == Format::Pe {
        f.add(
            Severity::Info,
            Category::Malware,
            "resolves APIs at run time",
            dynl,
        );
    }
    for (r, sev, title) in [
        (
            Risk::Persistence,
            Severity::Warn,
            "persistence APIs (registry / services)",
        ),
        (
            Risk::Keylogging,
            Severity::Warn,
            "keyboard state polling (keylogging)",
        ),
        (Risk::Crypto, Severity::Info, "cryptography APIs"),
        (
            Risk::Privilege,
            Severity::Info,
            "privilege / token manipulation APIs",
        ),
        (Risk::Network, Severity::Info, "network APIs"),
    ] {
        let list = risky(r);
        if !list.is_empty() {
            f.add(sev, Category::Malware, title, list);
        }
    }
    let urls: BTreeSet<String> = strings
        .iter()
        .flat_map(|s| {
            URL.find_iter(&s.text)
                .map(move |m| format!("{}: {}", s.place, m.as_str()))
        })
        .collect();
    if !urls.is_empty() {
        f.add(
            Severity::Warn,
            Category::Malware,
            "URLs",
            urls.into_iter().collect(),
        );
    }
    let ips: BTreeSet<String> = strings
        .iter()
        .flat_map(|s| {
            IPV4.find_iter(&s.text)
                .map(|m| m.as_str())
                .filter(|ip| {
                    !ip.starts_with("0.") && !ip.starts_with("255.") && !ip.starts_with("127.0.0.1")
                })
                .map(move |ip| format!("{}: {ip}", s.place))
        })
        .collect();
    if !ips.is_empty() {
        f.add(
            Severity::Info,
            Category::Malware,
            "IPv4 addresses",
            ips.into_iter().collect(),
        );
    }
    for &(needle, ci, sev, cat, title) in STRING_RULES {
        let hits: Vec<String> = strings
            .iter()
            .filter(|s| {
                if ci {
                    s.text.to_ascii_lowercase().contains(needle)
                } else {
                    s.text.contains(needle)
                }
            })
            .map(|s| format!("{}: {}", s.place, truncate(&s.text, 80)))
            .collect();
        if !hits.is_empty() {
            match f.0.iter_mut().find(|x| x.title == title) {
                Some(existing) => existing.evidence.extend(hits),
                None => f.add(sev, cat, title, hits),
            }
        }
    }

    // ---- structure ----------------------------------------------------------
    let report = info::analyze(bin);
    if let Some(p) = &report.packer {
        let title = match &p.name {
            Some(n) => format!("packed with {n}"),
            None => "possibly packed or encrypted".to_string(),
        };
        f.add(Severity::High, Category::Malware, title, p.reasons.clone());
    }
    if matches!(status("W^X"), Some((Status::Disabled, _))) {
        let detail = checks
            .items
            .iter()
            .find(|m| m.name == "W^X")
            .and_then(|m| m.detail.clone())
            .unwrap_or_default();
        f.add(
            Severity::High,
            Category::General,
            "writable and executable memory (RWX)",
            vec![detail],
        );
    }
    let high_entropy: Vec<String> = bin
        .sections
        .iter()
        .filter(|s| s.alloc && s.file_size >= 512)
        .filter_map(|s| {
            let e = entropy::shannon(bin.section_data(s));
            (e > entropy::PACKED_THRESHOLD && s.name != ".rsrc")
                .then(|| format!("{} ({e:.2})", s.full_name()))
        })
        .collect();
    if !high_entropy.is_empty() && report.packer.is_none() {
        f.add(
            Severity::Warn,
            Category::Malware,
            "high-entropy sections (compressed or encrypted data)",
            high_entropy,
        );
    }
    if let Details::Pe(p) = &bin.details {
        let odd: Vec<String> = bin
            .sections
            .iter()
            .filter(|s| {
                !STD_PE_SECTIONS.contains(&s.name.as_str())
                    && !s.name.starts_with(".debug")
                    && !s.name.starts_with('/')
            })
            .map(|s| s.name.clone())
            .collect();
        if !odd.is_empty() {
            f.add(
                Severity::Info,
                Category::Malware,
                "non-standard section names",
                odd,
            );
        }
        if !p.tls_callbacks.is_empty() {
            let named: Vec<(u64, Option<String>)> = p
                .tls_callbacks
                .iter()
                .map(|&a| (a, names.describe(a)))
                .collect();
            // C/C++/Rust runtimes register their own callbacks for thread-local data.
            let runtime = named.iter().all(|(_, n)| {
                n.as_deref()
                    .is_some_and(|n| n.contains("dyn_tls") || n.contains("tls_callback"))
            });
            let (sev, title) = if runtime {
                (Severity::Info, "TLS callbacks (language runtime)")
            } else {
                (
                    Severity::Warn,
                    "TLS callbacks run before the entry point (anti-debug / unpacking trick)",
                )
            };
            f.add(
                sev,
                Category::Malware,
                title,
                named
                    .iter()
                    .map(|(a, n)| {
                        format!("{a:#x} {}", n.as_deref().unwrap_or(""))
                            .trim_end()
                            .to_string()
                    })
                    .collect(),
            );
        }
        if let Some(o) = &p.overlay {
            f.add(
                Severity::Warn,
                Category::Malware,
                format!(
                    "{} bytes of overlay data after the image (appended payload / installer data)",
                    o.size
                ),
                vec![format!("file offset {:#x}", o.offset)],
            );
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(u64::MAX, |d| d.as_secs());
        if !p.reproducible && u64::from(p.timestamp) > now {
            f.add(
                Severity::Info,
                Category::Malware,
                "compile timestamp is in the future (forged)",
                vec![],
            );
        }
        if p.checksum != 0 && p.checksum != p.checksum_computed {
            f.add(
                Severity::Info,
                Category::Malware,
                "PE checksum does not match (modified after linking)",
                vec![],
            );
        }
        if p.signature.is_none() && !matches!(bin.kind, FileKind::Object) {
            f.add(
                Severity::Info,
                Category::Malware,
                "no Authenticode signature",
                vec![],
            );
        }
        if p.clr.is_some() {
            f.add(
                Severity::Info,
                Category::General,
                ".NET assembly: decompile with ILSpy/dnSpy for the real logic",
                vec![],
            );
        }
    }
    if let Details::Macho(m) = &bin.details
        && m.code_signature.is_none()
        && m.filetype == 2
    {
        f.add(
            Severity::Info,
            Category::Malware,
            "unsigned Mach-O executable",
            vec![],
        );
    }

    // ---- general ------------------------------------------------------------
    match report.stripped {
        Some(true) => f.add(
            Severity::Info,
            Category::General,
            "stripped: no symbol table (start from the entry point)",
            vec![],
        ),
        Some(false) if report.debug_info => f.add(
            Severity::Info,
            Category::General,
            "debug info present: source names and paths available",
            vec![],
        ),
        _ => {}
    }
    if let Some(e) = bin.elf() {
        let paths: Vec<String> = e.rpath.iter().chain(&e.runpath).cloned().collect();
        if !paths.is_empty() {
            f.add(
                Severity::Warn,
                Category::General,
                "RPATH/RUNPATH set (library hijacking if writable)",
                paths,
            );
        }
    }
    for w in &bin.warnings {
        f.add(
            Severity::Warn,
            Category::General,
            format!("loader: {w}"),
            vec![],
        );
    }

    let mut findings = f.0;
    findings.sort_by_key(|f| (f.severity, f.category));
    AutoReport {
        high: findings
            .iter()
            .filter(|x| x.severity == Severity::High)
            .count(),
        warn: findings
            .iter()
            .filter(|x| x.severity == Severity::Warn)
            .count(),
        info: findings
            .iter()
            .filter(|x| x.severity == Severity::Info)
            .count(),
        findings,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max - 3).collect::<String>() + "..."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regexes() {
        assert!(URL.is_match("see http://evil.example.com/payload.bin now"));
        assert!(!URL.is_match("http://"));
        assert!(IPV4.is_match("connect 10.13.37.1:4444"));
        assert!(!IPV4.is_match("version 1.2.300.4"));
        assert!(FLAG.is_match("FLAG{this_is_not_the_flag}"));
        assert!(FLAG.is_match("picoCTF{abc_123}"));
        assert!(!FLAG.is_match("{}"));
        assert!(
            WIN_FN.is_match("win") && WIN_FN.is_match("get_flag") && WIN_FN.is_match("giveShell")
        );
        assert!(!WIN_FN.is_match("window") && !WIN_FN.is_match("main"));
    }
}
