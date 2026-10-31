//! Rendering. Analyzer reports are turned into a small styled document
//! ([`Doc`]) by `layout`, which is then emitted by `pretty` (colors + Unicode
//! boxes) or `plain` (no color, ASCII). JSON bypasses the document and
//! serializes the reports directly.

pub mod json;
pub mod layout;
pub mod plain;
pub mod pretty;

use crate::analyzers::auto::AutoReport;
use crate::analyzers::checksec::{ChecksecReport, Status};
use crate::analyzers::disasm::{DisasmReport, InsnClass};
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
use crate::model::Perms;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Pretty,
    Plain,
    Json,
}

/// Semantic style of a piece of text; backends decide what it looks like.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tone {
    Normal,
    Dim,
    Bold,
    Key,
    Addr,
    Offset,
    Num,
    Hash,
    Path,
    Section,
    Library,
    Func,
    Object,
    Tls,
    Ifunc,
    FileSym,
    Good,
    Bad,
    Warn,
    Perm(Perms),
    /// Entropy value (bits/byte); pretty mode adds a level bar.
    Entropy(f64),
    /// A mitigation badge: backends prefix the text with a status glyph and
    /// never wrap inside it.
    Badge(Status),
    /// Separator between items (` · ` / `, `).
    Sep,
    /// Instruction mnemonic, colored by class.
    Insn(InsnClass),
    /// A raw byte in a hex dump, colored by value class.
    Byte(u8),
    /// A string literal.
    Str,
    /// Entropy bar of the given width (pretty: Unicode blocks, plain: `#`).
    Bar(f64, u8),
    /// One sparkline cell for an entropy value.
    Spark(f64),
}

#[derive(Debug, Clone)]
pub struct Span {
    pub text: String,
    pub tone: Tone,
}

impl Span {
    pub fn new(text: impl Into<String>, tone: Tone) -> Self {
        Span {
            text: text.into(),
            tone,
        }
    }
}

pub type Line = Vec<Span>;

#[derive(Debug, Clone)]
pub struct Row {
    pub key: String,
    pub lines: Vec<Line>,
}

#[derive(Debug, Clone, Default)]
pub struct Group {
    pub title: Option<String>,
    pub rows: Vec<Row>,
}

impl Group {
    pub fn new(title: Option<&str>) -> Self {
        Group {
            title: title.map(str::to_string),
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, key: &str, line: Line) {
        self.rows.push(Row {
            key: key.to_string(),
            lines: vec![line],
        });
    }

    pub fn rows(&mut self, key: &str, lines: Vec<Line>) {
        if !lines.is_empty() {
            self.rows.push(Row {
                key: key.to_string(),
                lines,
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct Panel {
    pub title: String,
    pub groups: Vec<Group>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

#[derive(Debug, Clone)]
pub struct Column {
    pub name: String,
    pub align: Align,
}

#[derive(Debug, Clone)]
pub struct Table {
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Span>>,
}

#[derive(Debug, Clone)]
pub enum Block {
    Panel(Panel),
    Heading {
        title: String,
        subtitle: Option<String>,
    },
    Table(Table),
    Note(Line),
    /// Pre-formatted listing (disassembly, hex dump): one entry per line.
    Lines(Vec<Line>),
}

#[derive(Debug, Clone, Default)]
pub struct Doc {
    pub blocks: Vec<Block>,
}

/// One requested view.
pub enum Report {
    Info(Box<InfoReport>),
    Sections(SectionsReport),
    Segments(SegmentsReport),
    Symbols(SymbolsReport),
    Auto(AutoReport),
    Checksec(ChecksecReport),
    Imports(ImportsReport),
    Exports(ExportsReport),
    Plt(PltReport),
    Got(GotReport),
    Relocs(RelocsReport),
    Entropy(EntropyReport),
    Strings(StringsReport),
    Find(FindReport),
    Xrefs(XrefsReport),
    Gadgets(GadgetsReport),
    Disasm(DisasmReport),
    Offsets(OffsetsReport),
    Hexdump(HexdumpReport),
}

impl Report {
    /// Key used for this view in JSON output.
    pub fn key(&self) -> &'static str {
        match self {
            Report::Info(_) => "info",
            Report::Sections(_) => "sections",
            Report::Segments(_) => "segments",
            Report::Symbols(_) => "symbols",
            Report::Auto(_) => "auto",
            Report::Checksec(_) => "checksec",
            Report::Imports(_) => "imports",
            Report::Exports(_) => "exports",
            Report::Plt(_) => "plt",
            Report::Got(_) => "got",
            Report::Relocs(_) => "relocs",
            Report::Entropy(_) => "entropy",
            Report::Strings(_) => "strings",
            Report::Find(_) => "find",
            Report::Xrefs(_) => "xrefs",
            Report::Gadgets(_) => "gadgets",
            Report::Disasm(_) => "disasm",
            Report::Offsets(_) => "offsets",
            Report::Hexdump(_) => "hexdump",
        }
    }
}

pub struct Output {
    pub mode: Mode,
    /// Terminal width in columns (pretty mode).
    pub width: usize,
}

pub fn render(reports: &[Report], file: &str, out: &Output) -> String {
    match out.mode {
        Mode::Json => json::render(file, reports),
        Mode::Pretty | Mode::Plain => {
            let mut s = String::new();
            for (i, r) in reports.iter().enumerate() {
                if i > 0 {
                    s.push('\n');
                }
                let doc = layout::doc(r);
                if out.mode == Mode::Pretty {
                    pretty::write(&doc, out.width, &mut s);
                } else {
                    plain::write(&doc, &mut s);
                }
            }
            s
        }
    }
}

/// Make text taken from a binary safe for a terminal: control characters
/// (including ESC, which could inject escape sequences) are shown as `\xNN`.
pub fn sanitize(text: &str) -> std::borrow::Cow<'_, str> {
    let clean = if text.is_ascii() {
        !text.bytes().any(|b| b < 0x20 || b == 0x7f)
    } else {
        !text.chars().any(is_unsafe_char)
    };
    if clean {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut s = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if is_unsafe_char(c) {
            s.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            s.push(c);
        }
    }
    std::borrow::Cow::Owned(s)
}

/// Display width of plain text (fast path for ASCII).
pub fn text_width(s: &str) -> usize {
    if s.is_ascii() {
        s.len()
    } else {
        unicode_width::UnicodeWidthStr::width(s)
    }
}

/// Append `n` spaces without allocating.
pub fn push_spaces(out: &mut String, mut n: usize) {
    const SPACES: &str = "                                                                ";
    while n > 0 {
        let k = n.min(SPACES.len());
        out.push_str(&SPACES[..k]);
        n -= k;
    }
}

/// C0/C1 controls and DEL (tabs too: they break column alignment).
fn is_unsafe_char(c: char) -> bool {
    c.is_control()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_escapes_control_chars() {
        assert_eq!(sanitize("main"), "main");
        assert_eq!(sanitize("evil\x1b[31m"), "evil\\x1b[31m");
        assert_eq!(sanitize("a\nb"), "a\\x0ab");
    }
}
