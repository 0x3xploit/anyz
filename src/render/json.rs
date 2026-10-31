//! JSON backend: one object with a key per requested view.

use serde::Serialize;

use super::Report;
use crate::analyzers::auto::AutoReport;
use crate::analyzers::checksec::ChecksecReport;
use crate::analyzers::disasm::DisasmReport;
use crate::analyzers::entropy::EntropyReport;
use crate::analyzers::find::FindReport;
use crate::analyzers::gadgets::GadgetsReport;
use crate::analyzers::hexdump::HexdumpReport;
use crate::analyzers::info::InfoReport;
use crate::analyzers::offsets::OffsetsReport;
use crate::analyzers::sections::{SectionsReport, SegmentsReport};
use crate::analyzers::strings::StringsReport;
use crate::analyzers::symbols::SymbolsReport;
use crate::analyzers::symbols::{ExportsReport, GotReport, ImportsReport, PltReport, RelocsReport};
use crate::analyzers::xrefs::XrefsReport;

#[derive(Serialize)]
struct JsonOut<'a> {
    file: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    info: Option<&'a InfoReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sections: Option<&'a SectionsReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    segments: Option<&'a SegmentsReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbols: Option<&'a SymbolsReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto: Option<&'a AutoReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checksec: Option<&'a ChecksecReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    imports: Option<&'a ImportsReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exports: Option<&'a ExportsReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plt: Option<&'a PltReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    got: Option<&'a GotReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relocs: Option<&'a RelocsReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entropy: Option<&'a EntropyReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    strings: Option<&'a StringsReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    find: Option<&'a FindReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    xrefs: Option<&'a XrefsReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gadgets: Option<&'a GadgetsReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disasm: Option<&'a DisasmReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offsets: Option<&'a OffsetsReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hexdump: Option<&'a HexdumpReport>,
}

pub fn render(file: &str, reports: &[Report]) -> String {
    let mut out = JsonOut {
        file,
        info: None,
        sections: None,
        segments: None,
        symbols: None,
        auto: None,
        checksec: None,
        imports: None,
        exports: None,
        plt: None,
        got: None,
        relocs: None,
        entropy: None,
        strings: None,
        find: None,
        xrefs: None,
        gadgets: None,
        disasm: None,
        offsets: None,
        hexdump: None,
    };
    for r in reports {
        match r {
            Report::Info(x) => out.info = Some(x),
            Report::Sections(x) => out.sections = Some(x),
            Report::Segments(x) => out.segments = Some(x),
            Report::Symbols(x) => out.symbols = Some(x),
            Report::Auto(x) => out.auto = Some(x),
            Report::Checksec(x) => out.checksec = Some(x),
            Report::Imports(x) => out.imports = Some(x),
            Report::Exports(x) => out.exports = Some(x),
            Report::Plt(x) => out.plt = Some(x),
            Report::Got(x) => out.got = Some(x),
            Report::Relocs(x) => out.relocs = Some(x),
            Report::Entropy(x) => out.entropy = Some(x),
            Report::Strings(x) => out.strings = Some(x),
            Report::Find(x) => out.find = Some(x),
            Report::Xrefs(x) => out.xrefs = Some(x),
            Report::Gadgets(x) => out.gadgets = Some(x),
            Report::Disasm(x) => out.disasm = Some(x),
            Report::Offsets(x) => out.offsets = Some(x),
            Report::Hexdump(x) => out.hexdump = Some(x),
        }
    }
    let mut s =
        serde_json::to_string_pretty(&out).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
    s.push('\n');
    s
}
