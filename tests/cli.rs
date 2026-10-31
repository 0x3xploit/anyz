//! End-to-end tests: run the `anyz` binary on the fixtures in tests/fixtures/bin.
//!
//! Expected values come from independent tools (llvm-readelf/llvm-objdump for
//! ELF and Mach-O, pefile for PE imphash), not from anyz itself.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bin")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn anyz(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anyz"))
        .args(args)
        .env_remove("FORCE_COLOR")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("NO_COLOR")
        .env("COLUMNS", "120")
        .output()
        .expect("failed to run anyz")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn json(args: &[&str]) -> Value {
    let mut full = args.to_vec();
    full.push("--json");
    let out = anyz(&full);
    assert!(
        out.status.success(),
        "anyz {args:?} failed: {}",
        stderr(&out)
    );
    serde_json::from_slice(&out.stdout).expect("invalid JSON")
}

fn info(name: &str) -> Value {
    json(&[&fixture(name)])["info"].clone()
}

/// (status, value) of a mitigation in the info report.
fn mitigation(info: &Value, name: &str) -> (String, String) {
    let m = info["mitigations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == name)
        .unwrap_or_else(|| panic!("no mitigation {name} in {:#}", info["mitigations"]));
    (
        m["status"].as_str().unwrap().to_string(),
        m["value"].as_str().unwrap().to_string(),
    )
}

fn status(info: &Value, name: &str) -> String {
    mitigation(info, name).0
}

fn has_mitigation(info: &Value, name: &str) -> bool {
    info["mitigations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["name"] == name)
}

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

#[test]
fn elf_vuln_is_a_classic_ctf_target() {
    let i = info("elf-x64-vuln");
    assert_eq!(i["format"], "elf");
    assert_eq!(i["format_label"], "ELF64");
    assert_eq!(i["kind"], "executable");
    assert_eq!(i["arch"], "x86-64");
    assert_eq!(i["bits"], 64);
    assert_eq!(i["endian"], "little");
    assert_eq!(i["os"], "Linux");
    assert_eq!(i["image_base"], 0x400000);
    assert_eq!(i["entry"]["va"], 0x401600);
    assert_eq!(i["entry"]["offset"], 0x600);
    assert_eq!(i["entry"]["section"], ".text");
    assert_eq!(i["entry"]["symbol"], "_start");
    assert_eq!(i["interpreter"], "/lib64/ld-linux-x86-64.so.2");
    assert_eq!(i["linking"], "dynamic");
    assert_eq!(i["libraries"][0]["name"], "libc.so.6");
    assert_eq!(i["stripped"], false);
    assert_eq!(i["details"]["abi_tag"], "Linux 3.2.0");
    assert_eq!(
        i["hashes"]["sha256"],
        "fa6f69c2e86ebc84bb1553d21e6320780235ef5430aae696c484646f244e332a"
    );

    assert_eq!(status(&i, "NX"), "enabled");
    assert_eq!(status(&i, "PIE"), "disabled");
    assert_eq!(
        mitigation(&i, "RELRO"),
        ("partial".into(), "partial".into())
    );
    assert_eq!(status(&i, "Canary"), "disabled");
    assert_eq!(status(&i, "FORTIFY"), "disabled");
    assert_eq!(status(&i, "W^X"), "enabled");
    assert!(!has_mitigation(&i, "IBT"), "IBT only listed when enabled");
    assert_eq!(i["counts"]["imports"], 6);

    let tc: Vec<&str> = i["toolchain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert!(tc.iter().any(|t| t.starts_with("Clang 18")), "{tc:?}");
    assert!(tc.iter().any(|t| t.starts_with("LLD 18")), "{tc:?}");
}

#[test]
fn elf_hardened_has_every_mitigation() {
    let i = info("elf-x64-hardened");
    assert_eq!(i["kind"], "PIE executable");
    assert_eq!(i["image_base"], 0);
    assert_eq!(i["entry"]["va"], 0x1630);
    for m in ["NX", "PIE", "Canary", "FORTIFY", "W^X", "IBT", "SHSTK"] {
        assert_eq!(status(&i, m), "enabled", "{m}");
    }
    assert_eq!(mitigation(&i, "RELRO"), ("enabled".into(), "full".into()));
    let tc = i["toolchain"].to_string();
    assert!(tc.contains("C++"), "{tc}");
}

#[test]
fn elf_static_rwx_has_no_mitigations() {
    let i = info("elf-x64-static");
    assert_eq!(i["linking"], "static");
    assert!(i["interpreter"].is_null());
    assert_eq!(i["entry"]["va"], 0x4003c0);
    for m in ["NX", "PIE", "Canary", "W^X"] {
        assert_eq!(status(&i, m), "disabled", "{m}");
    }
    assert_eq!(mitigation(&i, "RELRO").1, "none");
}

#[test]
fn stripped_elf_keeps_dynamic_symbols() {
    let i = info("elf-x64-vuln-stripped");
    assert_eq!(i["stripped"], true);
    assert!(
        i["entry"]["symbol"].is_null(),
        "no _start symbol once stripped"
    );
    assert_eq!(i["entry"]["va"], 0x401600);

    let s = json(&[&fixture("elf-x64-vuln-stripped"), "--symbols"])["symbols"].clone();
    let names: Vec<&str> = s["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"gets") && names.contains(&"system"),
        "{names:?}"
    );
    assert!(!names.contains(&"win"), "local symbols are gone");
    let gets = s["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "gets")
        .unwrap();
    assert_eq!(gets["version"], "GLIBC_2.2.5");
    assert_eq!(gets["library"], "libc.so.6");
    assert_eq!(gets["defined"], false);
}

#[test]
fn symbols_are_sorted_demangled_and_filterable() {
    let s = json(&[&fixture("elf-x64-vuln"), "-s", "^win$"])["symbols"].clone();
    let rows = s["symbols"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "win");
    assert_eq!(rows[0]["kind"], "func");
    assert_eq!(rows[0]["section"], ".text");
    assert!(s["total"].as_u64().unwrap() > 1);

    // Smart case: lower-case pattern matches case-insensitively.
    let s = json(&[&fixture("elf-x64-hardened"), "-s", "CHECK"])["symbols"].clone();
    assert_eq!(
        s["symbols"].as_array().unwrap().len(),
        0,
        "upper-case pattern is case-sensitive"
    );
    let s = json(&[&fixture("elf-x64-hardened"), "-s", "check"])["symbols"].clone();
    let row = &s["symbols"][0];
    assert_eq!(row["name"], "_ZN3ctf5checkEPKci");
    assert_eq!(row["demangled"], "ctf::check(char const*, int)");

    // Defined symbols come first, ordered by address.
    let all = json(&[&fixture("elf-x64-vuln"), "-s"])["symbols"]["symbols"].clone();
    let defined: Vec<u64> = all
        .as_array()
        .unwrap()
        .iter()
        .take_while(|r| r["defined"] == true && r["kind"] != "file")
        .map(|r| r["addr"].as_u64().unwrap())
        .collect();
    assert!(defined.windows(2).all(|w| w[0] <= w[1]), "{defined:?}");
}

#[test]
fn sections_and_segments_match_readelf() {
    let j = json(&[&fixture("elf-x64-vuln"), "-S", "-l"]);
    let secs = j["sections"]["sections"].as_array().unwrap();
    let text = secs.iter().find(|s| s["name"] == ".text").unwrap();
    assert_eq!(text["addr"], 0x401600);
    assert_eq!(text["offset"], 0x600);
    assert_eq!(text["perms"], "r-x");
    assert!(text["entropy"].as_f64().unwrap() > 0.0);
    let bss = secs.iter().find(|s| s["name"] == ".bss").unwrap();
    assert_eq!(bss["file_size"], 0);
    assert!(bss["entropy"].is_null());

    let segs = j["segments"]["segments"].as_array().unwrap();
    let interp = segs.iter().find(|s| s["name"] == "INTERP").unwrap();
    assert_eq!(interp["detail"], "/lib64/ld-linux-x86-64.so.2");
    assert_eq!(interp["sections"][0], ".interp");
    let loads: Vec<&Value> = segs.iter().filter(|s| s["name"] == "LOAD").collect();
    assert_eq!(loads.len(), 4);
    assert!(
        loads
            .iter()
            .any(|s| s["perms"] == "r-x" && s["sections"].to_string().contains(".text"))
    );
    let stack = segs.iter().find(|s| s["name"] == "GNU_STACK").unwrap();
    assert_eq!(stack["perms"], "rw-");
}

// ---------------------------------------------------------------------------
// PE
// ---------------------------------------------------------------------------

#[test]
fn pe_mingw_executable() {
    let i = info("pe-x64-mingw.exe");
    assert_eq!(i["format"], "pe");
    assert_eq!(i["format_label"], "PE32+");
    assert_eq!(i["kind"], "executable");
    assert_eq!(i["arch"], "x86-64");
    assert_eq!(i["abi"], "console");
    assert_eq!(i["image_base"], 0x140000000u64);
    assert_eq!(i["entry"]["va"], 0x140001400u64);
    assert_eq!(i["entry"]["symbol"], "mainCRTStartup");
    // Reference value from pefile.
    assert_eq!(i["hashes"]["imphash"], "0f589bc76cb138511854304e235ece69");
    assert_eq!(i["stripped"], false);
    assert_eq!(i["details"]["tls_callbacks"].as_array().unwrap().len(), 2);
    assert!(
        i["details"]["overlay"].is_null(),
        "COFF symbol table is not an overlay"
    );
    assert_eq!(i["details"]["checksum"], i["details"]["checksum_computed"]);

    assert_eq!(status(&i, "DEP"), "enabled");
    assert_eq!(status(&i, "ASLR"), "enabled");
    assert_eq!(status(&i, "High-entropy VA"), "enabled");
    assert_eq!(status(&i, "CFG"), "disabled");
    assert_eq!(status(&i, "SafeSEH"), "not_applicable");
    assert_eq!(status(&i, "Signed"), "disabled");
    let tc = i["toolchain"].to_string();
    assert!(tc.contains("GCC") && tc.contains("MinGW"), "{tc}");

    let libs: Vec<&str> = i["libraries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["name"].as_str().unwrap())
        .collect();
    assert_eq!(libs, ["KERNEL32.dll", "msvcrt.dll"]);
}

#[test]
fn pe_dll_has_exports_and_imphash() {
    let i = info("pe-x64-dll.dll");
    assert_eq!(i["kind"], "DLL");
    assert_eq!(i["hashes"]["imphash"], "a16d964d8134224a70796dcba5f1f2e7");
    assert_eq!(i["counts"]["exports"], 4);
    assert_eq!(i["stripped"], true);
}

#[test]
fn pe_msvc_x64_has_cfg_gs_and_rich_header() {
    let i = info("pe-x64-msvc.exe");
    assert_eq!(i["format_label"], "PE32+");
    // Reference values from pefile.
    assert_eq!(i["hashes"]["imphash"], "ccc32cedec1378763763127a01a7ea53");
    assert_eq!(i["details"]["load_config"]["guard_flags"], 0x17500);
    assert_eq!(i["details"]["has_rich_header"], true);
    assert_eq!(i["details"]["reproducible"], true);
    for m in ["DEP", "ASLR", "High-entropy VA", "CFG", "GS", "CET"] {
        assert_eq!(status(&i, m), "enabled", "{m}");
    }
    assert_eq!(status(&i, "SafeSEH"), "not_applicable");
    assert!(i["toolchain"].to_string().contains("MSVC"));
}

#[test]
fn pe_msvc_x86_has_safeseh() {
    let i = info("pe-x86-msvc.exe");
    assert_eq!(i["format_label"], "PE32");
    assert_eq!(i["arch"], "x86");
    assert_eq!(i["bits"], 32);
    assert_eq!(i["hashes"]["imphash"], "98b44418f90fefb6f857fcfb5e3f3ee6");
    // goblin drops these for a Size=0xc0 load config; anyz parses them itself.
    assert_eq!(i["details"]["load_config"]["se_handler_count"], 1);
    assert_eq!(i["details"]["load_config"]["guard_flags"], 0x17500);
    assert_eq!(mitigation(&i, "SafeSEH"), ("enabled".into(), "yes".into()));
    assert_eq!(status(&i, "CFG"), "enabled");
    assert_eq!(status(&i, "High-entropy VA"), "not_applicable");
}

// ---------------------------------------------------------------------------
// Mach-O
// ---------------------------------------------------------------------------

#[test]
fn macho_arm64_executable() {
    let i = info("macho-arm64");
    assert_eq!(i["format"], "macho");
    assert_eq!(i["format_label"], "Mach-O 64-bit");
    assert_eq!(i["arch"], "arm64");
    assert_eq!(i["kind"], "executable");
    assert_eq!(i["os"], "macOS");
    assert_eq!(i["image_base"], 0x100000000u64);
    // LC_MAIN entryoff 0x658 (llvm-objdump --private-headers)
    assert_eq!(i["entry"]["va"], 0x100000658u64);
    assert_eq!(i["entry"]["symbol"], "_main");
    assert_eq!(i["interpreter"], "/usr/lib/dyld");
    assert_eq!(i["libraries"][0]["name"], "/usr/lib/libSystem.B.dylib");
    assert_eq!(status(&i, "PIE"), "enabled");
    assert_eq!(
        mitigation(&i, "Code signature"),
        ("enabled".into(), "ad-hoc".into())
    );
    assert_eq!(status(&i, "Canary"), "enabled");
    assert_eq!(status(&i, "NX stack"), "enabled");
    assert_eq!(i["details"]["min_os"], "11.0");
    assert_eq!(i["details"]["code_signature"]["identifier"], "macho-arm64");
}

#[test]
fn macho_x64_is_unsigned() {
    let i = info("macho-x64");
    assert_eq!(i["arch"], "x86-64");
    assert_eq!(status(&i, "Code signature"), "disabled");
}

#[test]
fn fat_macho_slice_selection() {
    let path = fixture("macho-fat");
    let i = json(&[&path, "--slice", "arm64"])["info"].clone();
    assert_eq!(i["arch"], "arm64");
    assert_eq!(i["details"]["fat"]["selected"], 1);
    let slices: Vec<&str> = i["details"]["fat"]["slices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["arch"].as_str().unwrap())
        .collect();
    assert_eq!(slices, ["x86_64", "arm64"]);

    let i = json(&[&path, "--slice", "x86-64"])["info"].clone();
    assert_eq!(i["arch"], "x86-64");

    // Without --slice the host architecture is used, if present.
    let out = anyz(&[&path, "--json"]);
    if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        assert!(out.status.success(), "{}", stderr(&out));
        let i: Value = serde_json::from_slice(&out.stdout).unwrap();
        let want = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x86-64"
        };
        assert_eq!(i["info"]["arch"], want);
    } else {
        assert!(!out.status.success());
    }

    let out = anyz(&[&path, "--slice", "ppc"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("available: x86_64, arm64"),
        "{}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// Raw blobs, errors, output modes
// ---------------------------------------------------------------------------

#[test]
fn raw_shellcode_with_arch_and_base() {
    let i = json(&[
        &fixture("shellcode-x64.bin"),
        "--arch",
        "x86-64",
        "--base",
        "0x10000",
    ])["info"]
        .clone();
    assert_eq!(i["format"], "raw");
    assert_eq!(i["arch"], "x86-64");
    assert_eq!(i["image_base"], 0x10000);
    assert_eq!(i["entry"]["va"], 0x10000);
    assert_eq!(i["entry"]["offset"], 0);
    assert_eq!(i["file_size"], 27);
    assert!(i["mitigations"].as_array().unwrap().is_empty());

    let i = info("shellcode-x64.bin");
    assert_eq!(i["arch"], "unknown");
    assert!(i["entry"].is_null());
}

#[test]
fn flags_that_do_not_apply_produce_warnings() {
    let i = json(&[
        &fixture("elf-x64-vuln"),
        "--arch",
        "arm",
        "--slice",
        "arm64",
    ])["info"]
        .clone();
    let w = i["warnings"].to_string();
    assert!(
        w.contains("--arch only applies") && w.contains("--slice only applies"),
        "{w}"
    );
    assert_eq!(i["arch"], "x86-64");
}

fn scratch_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("anyz-test-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn malformed_inputs_fail_cleanly() {
    let dir = scratch_dir("malformed");
    let cases: &[(&str, usize)] = &[
        ("elf-x64-vuln", 64),
        ("elf-x64-vuln", 20),
        ("pe-x64-mingw.exe", 600),
        ("macho-fat", 100),
        ("macho-arm64", 40),
    ];
    for (name, len) in cases {
        let data = std::fs::read(fixture(name)).unwrap();
        let p = dir.join(format!("{name}.{len}"));
        std::fs::write(&p, &data[..*len]).unwrap();
        let out = anyz(&[p.to_str().unwrap()]);
        let err = stderr(&out);
        assert!(!err.contains("panicked"), "{name}[..{len}] panicked: {err}");
        if !out.status.success() {
            assert_eq!(out.status.code(), Some(1));
            assert!(err.starts_with("anyz: error:"), "{err}");
        }
    }

    let empty = dir.join("empty");
    std::fs::write(&empty, b"").unwrap();
    let out = anyz(&[empty.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("is empty"));

    let out = anyz(&[dir.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("is a directory"));

    let out = anyz(&[dir.join("missing").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("cannot open"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bad_arguments_are_rejected() {
    let out = anyz(&[&fixture("elf-x64-vuln"), "--arch", "z80"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown architecture"));
    let out = anyz(&[&fixture("elf-x64-vuln"), "--symbols", "("]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("invalid --symbols regex"));
}

#[test]
fn piped_output_is_plain_text() {
    let out = anyz(&[&fixture("elf-x64-hardened"), "-i", "-S", "-l", "-s"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        !text.contains('\x1b'),
        "no ANSI escapes when stdout is not a TTY"
    );
    assert!(text.is_ascii(), "plain mode is ASCII-only");
    assert!(text.contains("[+] PIE") && text.contains("RELRO (full)"));
    assert!(
        text.contains("Sections (") && text.contains("Segments (") && text.contains("Symbols (")
    );
    assert!(text.contains("ctf::check(char const*, int)"));
}

#[test]
fn force_color_and_no_color() {
    let out = Command::new(env!("CARGO_BIN_EXE_anyz"))
        .arg(fixture("elf-x64-vuln"))
        .env("FORCE_COLOR", "1")
        .env_remove("NO_COLOR")
        .output()
        .unwrap();
    let text = stdout(&out);
    assert!(text.contains("\x1b["), "FORCE_COLOR enables ANSI colors");
    assert!(text.contains('╭') && text.contains('✓'));

    let out = Command::new(env!("CARGO_BIN_EXE_anyz"))
        .arg(fixture("elf-x64-vuln"))
        .env("FORCE_COLOR", "1")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(
        !stdout(&out).contains('\x1b'),
        "NO_COLOR wins over FORCE_COLOR"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_anyz"))
        .args([fixture("elf-x64-vuln").as_str(), "--no-color"])
        .env("FORCE_COLOR", "1")
        .output()
        .unwrap();
    assert!(
        !stdout(&out).contains('\x1b'),
        "--no-color wins over FORCE_COLOR"
    );
}

#[test]
fn json_works_for_every_fixture_and_view() {
    for name in [
        "elf-x64-vuln",
        "elf-x64-vuln-stripped",
        "elf-x64-hardened",
        "elf-x64-static",
        "pe-x64-mingw.exe",
        "pe-x64-dll.dll",
        "pe-x64-msvc.exe",
        "pe-x86-msvc.exe",
        "macho-arm64",
        "macho-x64",
        "shellcode-x64.bin",
    ] {
        let j = json(&[&fixture(name), "-i", "-S", "-l", "-s"]);
        assert!(j["file"].as_str().unwrap().ends_with(name));
        for key in ["info", "sections", "segments", "symbols"] {
            assert!(j.get(key).is_some(), "{name}: missing {key}");
        }
    }
}

// ---------------------------------------------------------------------------
// Milestone 2: addresses, disassembly, offsets, hexdump
// ---------------------------------------------------------------------------

fn refs(insns: &Value) -> Vec<String> {
    insns
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["reference"]["name"].as_str().map(str::to_string))
        .collect()
}

fn strings_in(insns: &Value) -> Vec<String> {
    insns
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["reference"]["string"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn plt_stubs_match_objdump() {
    // llvm-objdump -d labels for elf-x64-vuln
    let i = info("elf-x64-vuln");
    let plt: Vec<(String, u64)> = i["details"]["plt"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["name"].as_str().unwrap().to_string(),
                e["addr"].as_u64().unwrap(),
            )
        })
        .collect();
    let want = [
        ("system", 0x4016f0),
        ("puts", 0x401700),
        ("gets", 0x401710),
        ("printf", 0x401720),
        ("setvbuf", 0x401730),
    ];
    assert_eq!(plt, want.map(|(n, a)| (n.to_string(), a)).to_vec());
    // CET .plt.sec stubs in the hardened binary
    let i = info("elf-x64-hardened");
    let secs: Vec<&str> = i["details"]["plt"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["section"].as_str().unwrap())
        .collect();
    assert!(
        !secs.is_empty() && secs.iter().all(|s| *s == ".plt.sec"),
        "{secs:?}"
    );
}

#[test]
fn disasm_main_resolves_calls_and_strings() {
    let d = json(&[&fixture("elf-x64-vuln"), "-d", "main"])["disasm"].clone();
    assert_eq!(d["function"], "main");
    assert_eq!(d["start"], 0x401690);
    assert_eq!(d["mode"], "x86-64");
    let insns = &d["instructions"];
    let names = refs(insns);
    for want in ["setvbuf@plt", "vuln", "puts@plt", "stdout"] {
        assert!(names.iter().any(|n| n == want), "{want} not in {names:?}");
    }
    let strings = strings_in(insns);
    assert!(
        strings
            .iter()
            .any(|s| s.contains("FLAG{this_is_not_the_flag}")),
        "{strings:?}"
    );
    let all = insns.as_array().unwrap();
    assert_eq!(all.last().unwrap()["mnemonic"], "ret");
    assert_eq!(all.last().unwrap()["class"], "ret");
    assert_eq!(all[0]["label"], "main");
    // exactly the function (symbol size 0x44)
    assert_eq!(d["end"], 0x401690 + 0x44);
}

#[test]
fn disasm_win_calls_system_with_bin_sh() {
    let d = json(&[&fixture("elf-x64-vuln"), "-d", "sym.win"])["disasm"].clone();
    let insns = d["instructions"].as_array().unwrap();
    let call = insns.iter().find(|i| i["class"] == "call").unwrap();
    assert_eq!(call["reference"]["name"], "system@plt");
    assert_eq!(call["reference"]["addr"], 0x4016f0);
    assert!(
        strings_in(&d["instructions"])
            .iter()
            .any(|s| s == "\"/bin/sh\"")
    );
    let text = stdout(&anyz(&[
        &fixture("elf-x64-vuln"),
        "-d",
        "win",
        "--syntax",
        "att",
    ]));
    assert!(
        text.contains("pushq") && text.contains("%rbp") && text.contains("AT&T"),
        "{text}"
    );
}

#[test]
fn disasm_ranges_and_counts() {
    let count = |args: &[&str]| -> usize {
        let path = fixture("elf-x64-vuln");
        let mut a = vec![path.as_str()];
        a.extend_from_slice(args);
        json(&a)["disasm"]["instructions"].as_array().unwrap().len()
    };
    assert_eq!(count(&["-d", "main", "-n", "3"]), 3);
    // push rbp; mov rbp,rsp; sub rsp,0x10 = 8 bytes
    assert_eq!(count(&["-d", "0x401690", "0x401698"]), 3);
    assert_eq!(count(&["-d", "main", "+8"]), 3);
    // no FROM: main
    assert_eq!(
        json(&[&fixture("elf-x64-vuln"), "-d"])["disasm"]["start"],
        0x401690
    );
    // stripped: falls back to the entry point
    let d = json(&[&fixture("elf-x64-vuln-stripped"), "-d", "-n", "5"])["disasm"].clone();
    assert_eq!(d["start"], 0x401600);
    assert_eq!(d["function"], "entry");
    // reversed range is an error
    let out = anyz(&[&fixture("elf-x64-vuln"), "-d", "main", "0x401000"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("not after"), "{}", stderr(&out));
}

#[test]
fn disasm_other_formats_and_archs() {
    let d = json(&[&fixture("macho-arm64"), "-d", "main"])["disasm"].clone();
    assert_eq!(d["mode"], "arm64");
    let names = refs(&d["instructions"]);
    assert!(names.iter().any(|n| n == "_setvbuf@stub"), "{names:?}");
    assert!(
        names.iter().any(|n| n == "___stack_chk_guard@got"),
        "{names:?}"
    );
    let strings = strings_in(&d["instructions"]);
    assert!(
        strings.iter().any(|s| s.contains("What's your name?")),
        "{strings:?}"
    );

    let d = json(&[&fixture("pe-x64-mingw.exe"), "-d", "main"])["disasm"].clone();
    let names = refs(&d["instructions"]);
    assert!(
        names.iter().any(|n| n == "KERNEL32.dll!IsDebuggerPresent"),
        "{names:?}"
    );

    let d = json(&[&fixture("pe-x86-msvc.exe"), "-d", "-n", "4"])["disasm"].clone();
    assert_eq!(d["mode"], "x86");

    let d = json(&[
        &fixture("shellcode-x64.bin"),
        "--arch",
        "x86-64",
        "--base",
        "0x1000",
        "-d",
    ])["disasm"]
        .clone();
    let insns = d["instructions"].as_array().unwrap();
    assert_eq!(insns.len(), 13);
    assert_eq!(insns.last().unwrap()["mnemonic"], "syscall");
    assert_eq!(insns.last().unwrap()["class"], "syscall");
}

#[test]
fn disasm_needs_a_supported_arch() {
    let out = anyz(&[&fixture("shellcode-x64.bin"), "-d"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--arch"), "{}", stderr(&out));
}

#[test]
fn offsets_translate_between_spaces() {
    let o = json(&[&fixture("elf-x64-vuln"), "-o", "main+0x2d"])["offsets"].clone();
    assert_eq!(o["va"], 0x4016bd);
    assert_eq!(o["rva"], 0x16bd);
    assert_eq!(o["offset"], 0x6bd);
    assert_eq!(o["section"]["name"], ".text");
    assert_eq!(o["section"]["delta"], 0xbd);
    assert_eq!(o["symbol"], "main+0x2d");

    let o = json(&[&fixture("elf-x64-vuln"), "-o", "stdout"])["offsets"].clone();
    assert!(o["offset"].is_null());
    assert_eq!(o["section"]["name"], ".bss");
    assert!(o["notes"].to_string().contains("no file backing"));

    let o = json(&[&fixture("pe-x64-msvc.exe"), "-o", "rva:0x1000"])["offsets"].clone();
    assert_eq!(o["va"], 0x140001000u64);
    assert_eq!(o["offset"], 0x400);
    assert_eq!(o["section"]["name"], ".text");

    let o = json(&[&fixture("elf-x64-vuln"), "-o", "off:0x30"])["offsets"].clone();
    assert_eq!(o["va"], 0x400030);
    assert!(o["section"].is_null());

    // Pointer slots can be named the way --got and --disasm print them.
    let o = json(&[&fixture("elf-x64-vuln"), "-o", "puts@got"])["offsets"].clone();
    assert_eq!(o["symbol"], "puts@got");
    for e in [
        "KERNEL32.dll!Sleep",
        "kernel32!Sleep",
        "Sleep@got",
        "sym.imp.Sleep",
    ] {
        let o = json(&[&fixture("pe-x64-mingw.exe"), "-o", e])["offsets"].clone();
        assert_eq!(o["va"], 0x14000f228u64, "{e}");
        assert_eq!(o["symbol"], "KERNEL32.dll!Sleep", "{e}");
    }
}

#[test]
fn hexdump_by_va_and_offset() {
    let h = json(&[&fixture("elf-x64-vuln"), "-x", "off:0", "16"])["hexdump"].clone();
    assert_eq!(h["space"], "offset");
    assert_eq!(h["bytes"], "7f454c46020101000000000000000000");
    let h = json(&[&fixture("elf-x64-vuln"), "-x", "main", "4"])["hexdump"].clone();
    assert_eq!(h["start"], 0x401690);
    assert_eq!(h["offset"], 0x690);
    assert_eq!(h["bytes"], "554889e5");
    assert_eq!(h["section"], ".text");
    // VA dumps stop at the end of the mapping: main is 0xb0 bytes before the end
    // of the r-x LOAD segment (readelf: 0x401600 + 0x140).
    let h = json(&[&fixture("elf-x64-vuln"), "-x", "main"])["hexdump"].clone();
    assert_eq!(h["bytes"].as_str().unwrap().len(), 2 * 0xb0);
    assert!(
        h["notes"]
            .to_string()
            .contains("end of the file-backed mapping")
    );
    // a file-offset dump keeps going
    let h = json(&[&fixture("elf-x64-vuln"), "-x", "off:0x690"])["hexdump"].clone();
    assert_eq!(h["bytes"].as_str().unwrap().len(), 2 * 256);

    let text = stdout(&anyz(&[&fixture("elf-x64-vuln"), "-x", "off:0", "16"]));
    assert!(
        text.contains("7f 45 4c 46") && text.contains("|.ELF"),
        "{text}"
    );

    let out = anyz(&[&fixture("elf-x64-vuln"), "-x", "stdout"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains(".bss"), "{}", stderr(&out));
}

#[test]
fn address_errors_explain_themselves() {
    let out = anyz(&[&fixture("elf-x64-vuln"), "-o", "mian"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("did you mean main"),
        "{}",
        stderr(&out)
    );
    let out = anyz(&[&fixture("pe-x64-msvc.exe"), "-x", "0x1000"]);
    assert!(stderr(&out).contains("rva:0x1000"), "{}", stderr(&out));
    let out = anyz(&[&fixture("pe-x64-msvc.exe"), "-d", "0x1000"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("rva:0x1000"), "{}", stderr(&out));
    // names are never re-interpreted as RVAs or offsets
    let out = anyz(&[&fixture("elf-x64-vuln"), "-d", "main+0x100000"]);
    assert!(
        stderr(&out).contains("mapped addresses span"),
        "{}",
        stderr(&out)
    );
    let out = anyz(&[&fixture("elf-x64-vuln"), "-x", "off:stdout"]);
    assert!(stderr(&out).contains("no file backing"), "{}", stderr(&out));
    let out = anyz(&[&fixture("elf-x64-vuln"), "-o", "main+"]);
    assert!(
        stderr(&out).contains("invalid address expression"),
        "{}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// Milestone 3: checksec, imports/exports, plt/got, relocs, entropy, strings
// ---------------------------------------------------------------------------

#[test]
fn checksec_view_has_details_and_extras() {
    let c = json(&[&fixture("elf-x64-vuln"), "--checksec"])["checksec"].clone();
    let names: Vec<&str> = c["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["NX", "PIE", "RELRO", "Canary", "FORTIFY", "W^X"]);
    let extra: Vec<(&str, &str)> = c["extra"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| (m["name"].as_str().unwrap(), m["verdict"].as_str().unwrap()))
        .collect();
    assert_eq!(
        extra,
        [
            ("RPATH", "good"),
            ("RUNPATH", "good"),
            ("TEXTREL", "good"),
            ("Stripped", "bad")
        ]
    );
    let text = stdout(&anyz(&[&fixture("elf-x64-vuln"), "--checksec"]));
    assert!(
        text.contains("[~] partial") && text.contains("fixed load address 0x400000"),
        "{text}"
    );
    assert!(
        text.contains("[+] none") && text.contains("[-] no "),
        "{text}"
    );
    // checksec alone does not print the info panel
    assert!(!text.contains("SHA256"));
}

#[test]
fn imports_grouped_with_risks() {
    let i = json(&[&fixture("elf-x64-vuln"), "-I"])["imports"].clone();
    assert_eq!(i["total"], 6);
    let libc = &i["libraries"][0];
    assert_eq!(libc["library"], "libc.so.6");
    let risk = |name: &str| {
        libc["imports"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .map(|r| r["risk"].clone())
            .unwrap()
    };
    assert_eq!(risk("gets"), "memory");
    assert_eq!(risk("system"), "exec");
    assert!(risk("puts").is_null());
    let gets = libc["imports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "gets")
        .unwrap();
    assert_eq!(gets["plt"], 0x401710);
    assert_eq!(gets["slot"], 0x403890);

    let i = json(&[&fixture("pe-x64-mingw.exe"), "-I"])["imports"].clone();
    let rows: Vec<&Value> = i["libraries"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|l| l["imports"].as_array().unwrap())
        .collect();
    let dbg = rows
        .iter()
        .find(|r| r["name"] == "IsDebuggerPresent")
        .unwrap();
    assert_eq!(dbg["risk"], "anti_debug");
    let valloc = rows.iter().find(|r| r["name"] == "VirtualAlloc").unwrap();
    assert_eq!(valloc["risk"], "exec_memory");
    assert!(i["risky"].as_u64().unwrap() >= 3);
    let text = stdout(&anyz(&[&fixture("elf-x64-vuln"), "-I"]));
    assert!(
        text.contains("[memory-unsafe]") && text.contains("[exec]"),
        "{text}"
    );
}

#[test]
fn exports_with_ordinals_and_forwarders() {
    let e = json(&[&fixture("pe-x64-dll.dll"), "-E"])["exports"].clone();
    let rows = e["exports"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    let fwd = rows.iter().find(|r| r["name"] == "TickCount").unwrap();
    assert_eq!(fwd["forwarder"], "KERNEL32.GetTickCount");
    assert_eq!(fwd["ordinal"], 4);
    let noname = rows.iter().find(|r| r["ordinal"] == 2).unwrap();
    assert!(noname["name"].is_null());
    let data = rows.iter().find(|r| r["name"] == "exported_data").unwrap();
    assert_eq!(data["kind"], "object");
    let text = stdout(&anyz(&[&fixture("pe-x64-dll.dll"), "-E"]));
    assert!(
        text.contains("-> KERNEL32.GetTickCount") && text.contains("(by ordinal)"),
        "{text}"
    );
}

#[test]
fn plt_and_got_views() {
    let j = json(&[&fixture("elf-x64-vuln"), "--plt", "--got"]);
    let plt = j["plt"]["entries"].as_array().unwrap();
    assert_eq!(plt.len(), 5);
    assert_eq!(plt[0]["name"], "system");
    assert_eq!(plt[0]["slot"], 0x403880);
    let got = j["got"]["entries"].as_array().unwrap();
    let puts = got.iter().find(|g| g["name"] == "puts").unwrap();
    assert_eq!(puts["kind"], "X86_64_JUMP_SLOT");
    assert_eq!(puts["section"], ".got.plt");
    // lazy binding: the slot initially points back into the PLT stub (stub + 6)
    assert_eq!(puts["value"], 0x401700 + 6);

    let j = json(&[&fixture("macho-arm64"), "--plt", "--got"]);
    assert_eq!(j["plt"]["entries"].as_array().unwrap().len(), 6);
    let kinds: Vec<&str> = j["got"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"lazy pointer") && kinds.contains(&"non lazy pointer"),
        "{kinds:?}"
    );

    let j = json(&[&fixture("pe-x64-msvc.exe"), "--plt", "--got"]);
    assert!(j["plt"]["note"].as_str().unwrap().contains("IAT"));
    let iat = j["got"]["entries"].as_array().unwrap();
    assert!(iat.iter().all(|g| g["kind"] == "IAT"));
    assert!(
        iat.iter()
            .any(|g| g["name"] == "KERNEL32.dll!IsDebuggerPresent")
    );
}

#[test]
fn relocations_view() {
    let r = json(&[&fixture("elf-x64-vuln"), "-r"])["relocs"].clone();
    assert_eq!(r["total"], 7);
    let rows = r["relocations"].as_array().unwrap();
    let copy = rows.iter().find(|x| x["kind"] == "R_X86_64_COPY").unwrap();
    assert_eq!(copy["symbol"], "stdout");
    assert_eq!(copy["section"], ".bss");
    let r = json(&[&fixture("pe-x64-msvc.exe"), "-r"])["relocs"].clone();
    let rows = r["relocations"].as_array().unwrap();
    assert!(
        !rows.is_empty()
            && rows
                .iter()
                .all(|x| x["kind"] == "DIR64" && x["table"] == ".reloc")
    );
}

#[test]
fn entropy_view() {
    let e = json(&[&fixture("elf-x64-vuln"), "-e"])["entropy"].clone();
    let blocks = e["blocks"].as_array().unwrap();
    assert!(!blocks.is_empty() && blocks.len() <= 64);
    assert!(
        blocks
            .iter()
            .all(|b| (0.0..=8.0).contains(&b.as_f64().unwrap()))
    );
    let fe = e["file_entropy"].as_f64().unwrap();
    assert!(fe > 0.0 && fe < 8.0);
    let bss = e["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == ".bss")
        .unwrap();
    assert!(bss["entropy"].is_null());
    let text = stdout(&anyz(&[&fixture("elf-x64-vuln"), "-e"]));
    assert!(
        text.contains("profile") && text.contains('#') && text.is_ascii(),
        "{text}"
    );
}

#[test]
fn strings_view() {
    let st = json(&[&fixture("elf-x64-vuln"), "-z"])["strings"].clone();
    let rows = st["strings"].as_array().unwrap();
    let find = |v: &str| rows.iter().find(|r| r["value"] == v).cloned();
    let flag = find("FLAG{this_is_not_the_flag}").expect("flag string");
    assert_eq!(flag["section"], ".rodata");
    assert_eq!(flag["va"], 0x400510);
    let sh = find("/bin/sh").expect("/bin/sh");
    assert_eq!(sh["va"], 0x400537);
    assert!(find("What's your name?").is_some());
    // -n raises the minimum length
    let st = json(&[&fixture("elf-x64-vuln"), "-z", "-n", "20"])["strings"].clone();
    assert!(
        st["strings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["value"].as_str().unwrap().len() >= 20)
    );
    assert_eq!(st["min_len"], 20);

    // UTF-16LE strings in a raw blob
    let dir = scratch_dir("utf16");
    let p = dir.join("wide.bin");
    let mut data = vec![0u8; 16];
    data.extend(
        "C:\\Windows\\evil.dll"
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    data.extend([0u8; 8]);
    std::fs::write(&p, &data).unwrap();
    let st = json(&[p.to_str().unwrap(), "-z", "--utf16"])["strings"].clone();
    let wide = st["strings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["encoding"] == "utf16")
        .unwrap()
        .clone();
    assert_eq!(wide["value"], "C:\\Windows\\evil.dll");
    assert_eq!(wide["offset"], 16);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Milestone 4: --auto, --gadgets, --find, --xrefs
// ---------------------------------------------------------------------------

fn findings(name: &str) -> Vec<Value> {
    json(&[&fixture(name), "--auto"])["auto"]["findings"]
        .as_array()
        .unwrap()
        .clone()
}

fn finding<'a>(all: &'a [Value], needle: &str) -> Option<&'a Value> {
    all.iter()
        .find(|f| f["title"].as_str().unwrap().contains(needle))
}

#[test]
fn auto_flags_the_ctf_target() {
    let all = findings("elf-x64-vuln");
    let r2w = finding(&all, "ret2win candidate").expect("ret2win finding");
    assert_eq!(r2w["severity"], "high");
    assert_eq!(r2w["category"], "ctf");
    assert!(
        r2w["evidence"].to_string().contains("win @ 0x401630"),
        "{r2w}"
    );
    let mem = finding(&all, "memory-unsafe").unwrap();
    assert_eq!(mem["severity"], "high");
    assert!(mem["evidence"].to_string().contains("gets"));
    assert!(finding(&all, "ret2system").is_some());
    assert!(finding(&all, "GOT is writable").is_some());
    assert!(
        finding(&all, "flag-like").unwrap()["evidence"]
            .to_string()
            .contains("FLAG{this_is_not_the_flag}")
    );
    // compiler metadata (.comment) must not produce findings
    assert!(finding(&all, "URLs").is_none(), "{all:?}");
    // highest severity first
    let sev: Vec<&str> = all
        .iter()
        .map(|f| f["severity"].as_str().unwrap())
        .collect();
    let rank = |s: &str| {
        ["high", "warn", "info"]
            .iter()
            .position(|x| *x == s)
            .unwrap()
    };
    assert!(sev.windows(2).all(|w| rank(w[0]) <= rank(w[1])), "{sev:?}");
}

#[test]
fn auto_on_hardened_and_static_binaries() {
    let all = findings("elf-x64-hardened");
    assert!(all.iter().all(|f| f["severity"] != "high"), "{all:?}");
    let all = findings("elf-x64-static");
    assert!(finding(&all, "executable stack").is_some());
    assert!(finding(&all, "RWX").is_some());
    // static: libc functions are symbols, not imports
    assert!(
        finding(&all, "memory-unsafe").unwrap()["evidence"]
            .to_string()
            .contains("gets")
    );
}

#[test]
fn auto_reports_malware_capabilities() {
    let all = findings("pe-x64-mingw.exe");
    assert_eq!(
        finding(&all, "anti-debugging").unwrap()["category"],
        "malware"
    );
    let tls = finding(&all, "TLS callbacks").unwrap();
    assert_eq!(
        tls["severity"], "info",
        "MinGW CRT callbacks are not suspicious: {tls}"
    );
    assert!(finding(&all, "no Authenticode signature").is_some());
    // --auto also prints the info panel
    let text = stdout(&anyz(&[&fixture("pe-x64-mingw.exe"), "--auto"]));
    assert!(
        text.contains("SHA256") && text.contains("Findings ("),
        "{text}"
    );
}

#[test]
fn gadgets_are_found_and_tagged() {
    let g = json(&[&fixture("elf-x64-vuln"), "-g"])["gadgets"].clone();
    let rows = g["gadgets"].as_array().unwrap();
    let pop = rows
        .iter()
        .find(|r| r["text"] == "pop rbp ; ret")
        .expect("pop rbp ; ret");
    assert_eq!(pop["addr"], 0x401643);
    assert_eq!(pop["bytes"], "5dc3");
    assert!(pop["tags"].to_string().contains("pop-reg"));
    let ret = rows.iter().find(|r| r["text"] == "ret").unwrap();
    assert!(ret["tags"].to_string().contains("align"));
    // deduplicated by text
    let mut texts: Vec<&str> = rows.iter().map(|r| r["text"].as_str().unwrap()).collect();
    let n = texts.len();
    texts.sort();
    texts.dedup();
    assert_eq!(texts.len(), n);
    // --depth bounds the gadget length
    let g = json(&[&fixture("elf-x64-vuln"), "-g", "--depth", "1"])["gadgets"].clone();
    assert!(
        g["gadgets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["instructions"].as_u64().unwrap() <= 2)
    );
    // the static binary has a syscall-free but larger gadget set; ARM64 works too
    let g = json(&[&fixture("macho-arm64"), "-g"])["gadgets"].clone();
    assert!(
        g["gadgets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["text"].as_str().unwrap().ends_with("ret"))
    );
}

#[test]
fn find_strings_and_byte_patterns() {
    let f = json(&[&fixture("elf-x64-vuln"), "-f", "/bin/sh"])["find"].clone();
    assert_eq!(f["kind"], "string");
    assert_eq!(f["total"], 1);
    let m = &f["matches"][0];
    assert_eq!(m["offset"], 0x537);
    assert_eq!(m["va"], 0x400537);
    assert_eq!(m["section"], ".rodata");

    // push rbp; mov rbp, rsp prologues: win, vuln, main
    let f = json(&[&fixture("elf-x64-vuln"), "-f", "55 48 89 e5"])["find"].clone();
    assert_eq!(f["kind"], "hex");
    let syms: Vec<&str> = f["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["symbol"].as_str().unwrap())
        .collect();
    assert_eq!(syms, ["win", "vuln", "main"]);
    let f = json(&[&fixture("elf-x64-vuln"), "-f", "e8 ?? ?? ?? ??"])["find"].clone();
    assert!(f["total"].as_u64().unwrap() >= 5);
    let f = json(&[&fixture("elf-x64-vuln"), "-f", "hex:7f454c46"])["find"].clone();
    assert_eq!(f["matches"][0]["offset"], 0);

    let out = anyz(&[&fixture("elf-x64-vuln"), "-f", "hex:zz"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("not a hex byte"), "{}", stderr(&out));
}

#[test]
fn xrefs_find_calls_and_data_references() {
    let x = json(&[&fixture("elf-x64-vuln"), "-X", "puts"])["xrefs"].clone();
    let code: Vec<&str> = x["refs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["kind"] == "code")
        .map(|r| r["function"].as_str().unwrap())
        .collect();
    assert_eq!(code, ["vuln+0x12", "main+0x37"]);

    let x = json(&[&fixture("elf-x64-vuln"), "-X", "stdout"])["xrefs"].clone();
    let refs = x["refs"].as_array().unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0]["kind"], "data");
    assert_eq!(refs[0]["function"], "main+0xf");

    let x = json(&[&fixture("elf-x64-vuln"), "-X", "win"])["xrefs"].clone();
    assert_eq!(
        x["total"], 0,
        "win is never called: that is the point of ret2win"
    );

    // PE: the call goes through the IAT slot
    let x = json(&[&fixture("pe-x64-mingw.exe"), "-X", "IsDebuggerPresent"])["xrefs"].clone();
    assert!(
        x["refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kind"] == "slot" && r["function"] == "main+0xa")
    );

    // Mach-O: bl to the stub
    let x = json(&[&fixture("macho-arm64"), "-X", "puts"])["xrefs"].clone();
    assert!(
        x["refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kind"] == "code")
    );
}
