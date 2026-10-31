//! anyz entry point: parse the command line, load the binary, run the
//! requested analyzers and hand the reports to the renderer.

use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use owo_colors::OwoColorize;

use anyz::analyzers::{
    auto, checksec, disasm, entropy, find, gadgets, hexdump, info, offsets, sections, strings,
    symbols, xrefs,
};
use anyz::cli::Cli;
use anyz::loader::{self, LoadOptions};
use anyz::render::{self, Mode, Output, Report};

/// Stack for the analysis thread: hostile inputs can drive the demanglers into
/// deep (bounded) recursion, and Windows gives the main thread only 1 MiB.
const WORKER_STACK: usize = 64 << 20;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mode = output_mode(&cli);
    let result = std::thread::Builder::new()
        .name("anyz".into())
        .stack_size(WORKER_STACK)
        .spawn(move || run(&cli, mode))
        .map_err(anyhow::Error::from)
        .and_then(|worker| {
            worker.join().unwrap_or_else(|_| {
                Err(anyhow::anyhow!(
                    "internal error (this is a bug in anyz, please report it)"
                ))
            })
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            print_error(&e);
            ExitCode::from(1)
        }
    }
}

fn env_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty() && v != "0")
}

/// JSON if asked; otherwise colors only on a capable terminal unless forced.
fn output_mode(cli: &Cli) -> Mode {
    if cli.json {
        return Mode::Json;
    }
    if cli.no_color || std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return Mode::Plain;
    }
    let forced = env_set("FORCE_COLOR") || env_set("CLICOLOR_FORCE");
    if !forced && !io::stdout().is_terminal() {
        return Mode::Plain;
    }
    if enable_ansi_support::enable_ansi_support().is_err() && !forced {
        return Mode::Plain; // legacy Windows console without VT processing
    }
    Mode::Pretty
}

fn terminal_width() -> usize {
    if let Some(w) = std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.parse::<usize>().ok())
    {
        return w.max(40);
    }
    comfy_table::Table::new()
        .width()
        .map_or(100, |w| usize::from(w).max(40))
}

fn run(cli: &Cli, mode: Mode) -> Result<()> {
    let opts = LoadOptions {
        arch: cli.arch.clone(),
        base: cli.base,
        slice: cli.slice.clone(),
    };
    let bin = loader::load(&cli.file, &opts)?;

    let mut reports = Vec::new();
    let show_info = cli.info || cli.auto || !cli.has_view_flags();
    if show_info {
        reports.push(Report::Info(Box::new(info::analyze(&bin))));
    } else {
        // The info panel normally shows loader warnings; surface them here instead.
        for w in &bin.warnings {
            eprintln!("anyz: warning: {w}");
        }
    }
    if cli.auto {
        reports.push(Report::Auto(auto::analyze(&bin)));
    }
    if cli.checksec {
        reports.push(Report::Checksec(checksec::analyze(&bin)));
    }
    if cli.sections {
        reports.push(Report::Sections(sections::sections(&bin)));
    }
    if cli.segments {
        reports.push(Report::Segments(sections::segments(&bin)));
    }
    if cli.entropy {
        reports.push(Report::Entropy(entropy::analyze(&bin)));
    }
    if let Some(pattern) = &cli.symbols {
        let filter = match pattern.as_deref().filter(|p| !p.is_empty()) {
            Some(p) => Some(
                symbols::build_filter(p)
                    .with_context(|| format!("invalid --symbols regex '{p}'"))?,
            ),
            None => None,
        };
        reports.push(Report::Symbols(symbols::analyze(&bin, filter.as_ref())));
    }
    if cli.imports {
        reports.push(Report::Imports(symbols::imports(&bin)));
    }
    if cli.exports {
        reports.push(Report::Exports(symbols::exports(&bin)));
    }
    if cli.plt {
        reports.push(Report::Plt(symbols::plt(&bin)));
    }
    if cli.got {
        reports.push(Report::Got(symbols::got(&bin)));
    }
    if cli.relocs {
        reports.push(Report::Relocs(symbols::relocs(&bin)));
    }
    if cli.strings {
        let min = cli.count.unwrap_or(strings::DEFAULT_MIN_LEN);
        reports.push(Report::Strings(strings::analyze(&bin, min, cli.utf16)));
    }
    if let Some(pattern) = &cli.find {
        reports.push(Report::Find(find::analyze(&bin, pattern)?));
    }
    if let Some(expr) = &cli.xrefs {
        reports.push(Report::Xrefs(xrefs::analyze(&bin, expr)?));
    }
    if cli.gadgets {
        reports.push(Report::Gadgets(gadgets::analyze(&bin, cli.depth)?));
    }
    if let Some(expr) = &cli.offsets {
        reports.push(Report::Offsets(offsets::analyze(&bin, expr)?));
    }
    if let Some(args) = &cli.hexdump {
        let len = args.get(1).map(String::as_str);
        reports.push(Report::Hexdump(hexdump::analyze(&bin, &args[0], len)?));
    }
    if let Some(args) = &cli.disasm {
        let req = disasm::DisasmRequest {
            from: args.first().cloned(),
            to: args.get(1).cloned(),
            count: cli.count,
            syntax: cli.syntax,
            thumb: cli.thumb,
        };
        reports.push(Report::Disasm(disasm::analyze(&bin, &req)?));
    }

    let out = Output {
        mode,
        width: terminal_width(),
    };
    let text = render::render(&reports, &bin.path.display().to_string(), &out);
    write_stdout(&text)
}

/// Write everything at once; a closed pipe (`| head`) is not an error.
fn write_stdout(text: &str) -> Result<()> {
    let mut out = io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(e).context("cannot write output"),
        _ => Ok(()),
    }
}

fn print_error(e: &anyhow::Error) {
    let color = io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let label = "anyz: error:";
    if color {
        eprintln!("{} {e:#}", label.red().bold());
    } else {
        eprintln!("{label} {e:#}");
    }
}
