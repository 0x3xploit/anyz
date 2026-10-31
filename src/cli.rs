//! Command-line interface (clap derive).

use std::path::PathBuf;

use clap::{Parser, ValueHint};

use crate::analyzers::disasm::Syntax;
use crate::model::ArchSpec;

const AFTER_HELP: &str = "\
Examples:
  anyz chall                        info panel: format, hashes, mitigations
  anyz chall --auto                 info panel + findings (ret2win? injection?)
  anyz chall -S -s win              sections, and symbols matching /win/
  anyz chall -d main                disassemble main; calls resolve to names
  anyz chall -d 0x401136 -n 20      20 instructions from an address
  anyz chall -o main+0x20           VA, RVA, file offset and section of it
  anyz chall -x off:0 64            hex dump of the first 64 bytes of the file
  anyz chall -X puts                who calls puts (through the PLT or GOT)
  anyz chall -g | grep 'pop rdi'    ROP gadgets
  anyz mal.exe -f 'e8 ?? ?? ?? ??'  byte pattern with wildcards
  anyz mal.exe -I --json | jq       any view as JSON
  anyz sc.bin --arch x86-64 -d      disassemble raw shellcode
  anyz fat.bin --slice arm64        one slice of a fat Mach-O

Colors are disabled automatically when stdout is not a terminal or NO_COLOR is
set; FORCE_COLOR=1 forces them on (e.g. for `less -R`).";

#[derive(Debug, Parser)]
#[command(
    name = "anyz",
    bin_name = "anyz",
    version,
    about = "Binary triage for ELF, PE and Mach-O: file + readelf + checksec + rabin2 in one command",
    after_help = AFTER_HELP
)]
pub struct Cli {
    /// Binary to analyze (ELF, PE, Mach-O, fat Mach-O, or a raw blob)
    #[arg(value_name = "BINARY", value_hint = ValueHint::FilePath)]
    pub file: PathBuf,

    /// Show the info panel (the default when no other view is selected)
    #[arg(short = 'i', long, help_heading = "Views")]
    pub info: bool,

    /// Section table: address, offset, size, permissions, entropy
    #[arg(short = 'S', long, help_heading = "Views")]
    pub sections: bool,

    /// Segments / program headers with the sections they map
    #[arg(short = 'l', long, help_heading = "Views")]
    pub segments: bool,

    /// Symbol table (demangled); optional REGEX filter, case-insensitive unless it has capitals
    #[arg(short = 's', long, value_name = "REGEX", num_args = 0..=1, help_heading = "Views")]
    pub symbols: Option<Option<String>>,

    /// Mitigations with details: NX, PIE, RELRO, canary, FORTIFY, CFG, SafeSEH, ...
    #[arg(long, help_heading = "Views")]
    pub checksec: bool,

    /// Imports grouped by library; risky APIs (gets, system, WriteProcessMemory, ...) highlighted
    #[arg(short = 'I', long, help_heading = "Views")]
    pub imports: bool,

    /// Exported symbols (with ordinals and forwarders for PE)
    #[arg(short = 'E', long, help_heading = "Views")]
    pub exports: bool,

    /// PLT stubs (ELF) / symbol stubs (Mach-O) and the functions they call
    #[arg(long, help_heading = "Views")]
    pub plt: bool,

    /// GOT slots (ELF, Mach-O) or IAT entries (PE) with names and stored values
    #[arg(long, help_heading = "Views")]
    pub got: bool,

    /// Relocation entries
    #[arg(short = 'r', long, help_heading = "Views")]
    pub relocs: bool,

    /// Entropy per section with bars, plus a whole-file profile
    #[arg(short = 'e', long, help_heading = "Views")]
    pub entropy: bool,

    /// Printable strings with offset, VA and section (minimum length: -n, default 4)
    #[arg(short = 'z', long, help_heading = "Views")]
    pub strings: bool,

    /// With --strings: also extract UTF-16LE strings
    #[arg(long, help_heading = "Views")]
    pub utf16: bool,

    /// Findings: exploitation hints for CTFs and capabilities for malware triage (plus the info panel)
    #[arg(short = 'a', long, help_heading = "Analysis")]
    pub auto: bool,

    /// ROP gadgets ending in a return, deduplicated
    #[arg(short = 'g', long, help_heading = "Analysis")]
    pub gadgets: bool,

    /// Maximum instructions before the return for --gadgets
    #[arg(long, value_name = "N", default_value_t = 4, help_heading = "Analysis")]
    pub depth: usize,

    /// Search for a string or bytes: "de ad ?? ef", 0x..., hex:..., str:..., wide:...
    #[arg(short = 'f', long, value_name = "PATTERN", help_heading = "Analysis")]
    pub find: Option<String>,

    /// Instructions that reference ADDR (calls, jumps, RIP-relative / adrp / auipc data refs)
    #[arg(short = 'X', long, value_name = "ADDR", help_heading = "Analysis")]
    pub xrefs: Option<String>,

    /// Print JSON instead of tables (works with every view)
    #[arg(short = 'j', long, help_heading = "Output")]
    pub json: bool,

    /// Plain output: no colors, no box drawing
    #[arg(long, help_heading = "Output")]
    pub no_color: bool,

    /// Architecture of a raw blob / shellcode (x86, x86-64, arm, thumb, arm64, mips, riscv64, ...)
    #[arg(long, value_name = "ARCH", value_parser = parse_arch, help_heading = "Loading")]
    pub arch: Option<ArchSpec>,

    /// Load address of a raw blob (hex 0x... or decimal)
    #[arg(long, value_name = "ADDR", value_parser = parse_number, help_heading = "Loading")]
    pub base: Option<u64>,

    /// Slice of a fat Mach-O to analyze (arm64, x86_64, ...); defaults to the host architecture
    #[arg(long, value_name = "ARCH", help_heading = "Loading")]
    pub slice: Option<String>,

    /// Disassemble FROM [TO] (TO may be +LEN); a sized symbol gives the whole function.
    /// Without FROM: main, else the entry point
    #[arg(short = 'd', long, value_names = ["FROM", "TO"], num_args = 0..=2, help_heading = "Code")]
    pub disasm: Option<Vec<String>>,

    /// Number of instructions for --disasm; minimum string length for --strings (default 4)
    #[arg(short = 'n', long, value_name = "N", help_heading = "Code")]
    pub count: Option<usize>,

    /// x86 assembly syntax for --disasm
    #[arg(long, value_enum, value_name = "SYNTAX", help_heading = "Code")]
    pub syntax: Option<Syntax>,

    /// Decode ARM code as Thumb (also automatic for odd addresses and Thumb symbols)
    #[arg(long, help_heading = "Code")]
    pub thumb: bool,

    /// Show an address as VA, RVA and file offset with its section and symbol
    #[arg(short = 'o', long, value_name = "ADDR", help_heading = "Code")]
    pub offsets: Option<String>,

    /// Hex dump LEN bytes (default 256) at ADDR; use off:N for raw file offsets
    #[arg(short = 'x', long, value_names = ["ADDR", "LEN"], num_args = 1..=2, help_heading = "Code")]
    pub hexdump: Option<Vec<String>>,
}

impl Cli {
    /// Any view other than the info panel was requested.
    pub fn has_view_flags(&self) -> bool {
        self.sections
            || self.segments
            || self.symbols.is_some()
            || self.checksec
            || self.imports
            || self.exports
            || self.plt
            || self.got
            || self.relocs
            || self.entropy
            || self.strings
            || self.disasm.is_some()
            || self.offsets.is_some()
            || self.hexdump.is_some()
            || self.gadgets
            || self.find.is_some()
            || self.xrefs.is_some()
    }
}

fn parse_arch(s: &str) -> Result<ArchSpec, String> {
    ArchSpec::parse(s).ok_or_else(|| {
        format!(
            "unknown architecture '{s}' (supported: {})",
            ArchSpec::NAMES
        )
    })
}

/// `0x401000`, `4198400`, `0b1010`, `0o777`, with optional `_` separators.
pub fn parse_number(s: &str) -> Result<u64, String> {
    crate::addr::parse_number(s)
        .ok_or_else(|| format!("'{s}' is not a valid number (use 0x... for hex)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn numbers() {
        assert_eq!(parse_number("0x401000"), Ok(0x401000));
        assert_eq!(parse_number("4198400"), Ok(4198400));
        assert_eq!(parse_number("0X10"), Ok(16));
        assert_eq!(parse_number("0x40_0000"), Ok(0x400000));
        assert!(parse_number("0x").is_err());
        assert!(parse_number("main").is_err());
        assert!(parse_number("0x1ffffffffffffffff").is_err());
    }

    #[test]
    fn optional_symbol_regex() {
        let c = Cli::try_parse_from(["anyz", "bin", "--symbols"]).unwrap();
        assert_eq!(c.symbols, Some(None));
        let c = Cli::try_parse_from(["anyz", "bin", "-s", "win"]).unwrap();
        assert_eq!(c.symbols, Some(Some("win".into())));
        let c = Cli::try_parse_from(["anyz", "bin"]).unwrap();
        assert_eq!(c.symbols, None);
        assert!(!c.has_view_flags());
    }
}
