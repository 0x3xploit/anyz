//! Robustness: mutated and truncated fixtures must never panic anywhere in the
//! pipeline (loader, analyzers, renderers), only load or fail with an error.

use std::path::PathBuf;

use anyz::analyzers::{
    auto, checksec, disasm, entropy, find, gadgets, hexdump, info, offsets, sections, strings,
    symbols, xrefs,
};
use anyz::loader::{self, LoadOptions};
use anyz::model::Data;
use anyz::render::{self, Mode, Output, Report};

const FIXTURES: &[&str] = &[
    "elf-x64-vuln",
    "elf-x64-hardened",
    "elf-x64-static",
    "pe-x64-dll.dll",
    "pe-x64-msvc.exe",
    "pe-x86-msvc.exe",
    "macho-arm64",
    "macho-fat",
];

/// Small deterministic PRNG (xorshift64*), so failures are reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn run_pipeline(name: &str, bytes: Vec<u8>) {
    let opts = LoadOptions::default();
    let keep = bytes.clone();
    let bin = match loader::load_data(PathBuf::from(name), Data::from_vec(bytes), &opts) {
        Ok(b) => b,
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.contains("parser gave up") {
                // Keep the input so the crash can be reproduced with the CLI.
                let dump = std::env::temp_dir().join(format!("anyz-crash-{name}"));
                let _ = std::fs::write(&dump, &keep);
                panic!(
                    "{name}: parser panicked: {msg} (input saved to {})",
                    dump.display()
                );
            }
            return;
        }
    };
    let mut reports = vec![
        Report::Info(Box::new(info::analyze(&bin))),
        Report::Sections(sections::sections(&bin)),
        Report::Segments(sections::segments(&bin)),
        Report::Symbols(symbols::analyze(&bin, None)),
        Report::Checksec(checksec::analyze(&bin)),
        Report::Imports(symbols::imports(&bin)),
        Report::Exports(symbols::exports(&bin)),
        Report::Plt(symbols::plt(&bin)),
        Report::Got(symbols::got(&bin)),
        Report::Relocs(symbols::relocs(&bin)),
        Report::Entropy(entropy::analyze(&bin)),
        Report::Strings(strings::analyze(&bin, 4, true)),
    ];
    // Errors (unmapped addresses, unknown arch) are fine; panics are not.
    let req = disasm::DisasmRequest {
        count: Some(64),
        ..Default::default()
    };
    if let Ok(d) = disasm::analyze(&bin, &req) {
        reports.push(Report::Disasm(d));
    }
    if let Ok(o) = offsets::analyze(&bin, "entry") {
        reports.push(Report::Offsets(o));
    }
    if let Ok(h) = hexdump::analyze(&bin, "off:0", Some("64")) {
        reports.push(Report::Hexdump(h));
    }
    reports.push(Report::Auto(auto::analyze(&bin)));
    if let Ok(f) = find::analyze(&bin, "e8 ?? ?? ?? ??") {
        reports.push(Report::Find(f));
    }
    if let Ok(x) = xrefs::analyze(&bin, "entry") {
        reports.push(Report::Xrefs(x));
    }
    if let Ok(g) = gadgets::analyze(&bin, 3) {
        reports.push(Report::Gadgets(g));
    }
    for mode in [Mode::Pretty, Mode::Plain, Mode::Json] {
        let out = render::render(&reports, name, &Output { mode, width: 100 });
        assert!(!out.is_empty());
    }
}

/// Mirror the CLI, which runs the pipeline on a 64 MiB-stack worker thread.
fn with_big_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e));
}

#[test]
fn mutated_fixtures_never_panic() {
    with_big_stack(fuzz_fixtures);
}

fn fuzz_fixtures() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bin");
    // ANYZ_FUZZ_ROUNDS / ANYZ_FUZZ_SEED allow longer local campaigns.
    let rounds: usize = std::env::var("ANYZ_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);
    let seed: u64 = std::env::var("ANYZ_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    let mut rng = Rng(seed | 1);
    for name in FIXTURES {
        let orig = std::fs::read(dir.join(name)).unwrap();
        for round in 0..rounds {
            let mut data = orig.clone();
            // Corrupt a handful of bytes, biased towards the headers.
            for _ in 0..1 + rng.below(12) {
                let span = if rng.below(2) == 0 {
                    data.len().min(0x400)
                } else {
                    data.len()
                };
                let i = rng.below(span);
                data[i] = rng.next() as u8;
            }
            if round % 4 == 0 {
                let keep = 1 + rng.below(data.len());
                data.truncate(keep);
            }
            if std::env::var_os("ANYZ_FUZZ_TRACE").is_some() {
                // Hard crashes (stack overflow) abort the process: keep the input first.
                let _ = std::fs::write(std::env::temp_dir().join("anyz-fuzz-current"), &data);
            }
            run_pipeline(name, data);
        }
    }
}

#[test]
fn every_prefix_of_a_small_elf_is_handled() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bin/elf-x64-vuln");
    let orig = std::fs::read(path).unwrap();
    for len in (1..orig.len()).step_by(37) {
        run_pipeline("prefix", orig[..len].to_vec());
    }
}
