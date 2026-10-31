//! Terminal backend: colors (owo-colors for panels, comfy-table's own cell
//! styling for tables) and Unicode box drawing.

use comfy_table::{
    Attribute, Cell, CellAlignment, Color, ContentArrangement, ContentLineStyle, LineStyle,
    Table as CTable, TableStyle,
};
use owo_colors::{OwoColorize, Style};
use unicode_width::UnicodeWidthStr;

use super::{Align, Block, Doc, Line, Panel, Span, Table, Tone, sanitize};
use crate::analyzers::checksec::Status;

const TABLE_STYLE: TableStyle = TableStyle::new()
    .top_border(LineStyle::new('╭', '─', '┬', '╮'))
    .header_lines(ContentLineStyle::new('│', '│', '│'))
    .header_separator(LineStyle::new('├', '─', '┼', '┤'))
    .content_lines(ContentLineStyle::new('│', '│', '│'))
    .bottom_border(LineStyle::new('╰', '─', '┴', '╯'));

/// Backend-neutral color names, mapped to owo-colors and comfy-table below.
#[derive(Clone, Copy)]
enum C {
    Red,
    Green,
    Yellow,
    Magenta,
    Cyan,
    Grey,
    BrightBlue,
    BrightMagenta,
}

fn paint_of(tone: Tone) -> (Option<C>, bool) {
    use Tone::*;
    match tone {
        Normal | Num | Hash => (None, false),
        Dim | Sep | FileSym => (Some(C::Grey), false),
        Bold | Path => (None, true),
        Key => (Some(C::Cyan), false),
        Addr => (Some(C::Yellow), false),
        Offset => (Some(C::Cyan), false),
        Section => (Some(C::Magenta), false),
        Library => (Some(C::BrightBlue), false),
        Func => (Some(C::Green), false),
        Object => (Some(C::Cyan), false),
        Tls | Ifunc => (Some(C::BrightMagenta), false),
        Good => (Some(C::Green), false),
        Bad => (Some(C::Red), false),
        Warn => (Some(C::Yellow), false),
        Perm(p) => {
            if p.is_wx() {
                (Some(C::Red), true)
            } else if p.x {
                (Some(C::BrightBlue), false)
            } else if p.w {
                (Some(C::Yellow), false)
            } else if p.r {
                (Some(C::Green), false)
            } else {
                (Some(C::Grey), false)
            }
        }
        Entropy(e) => {
            if e > crate::analyzers::entropy::PACKED_THRESHOLD {
                (Some(C::Red), true)
            } else if e >= 6.0 {
                (Some(C::Yellow), false)
            } else if e < 1.0 {
                (Some(C::Grey), false)
            } else {
                (None, false)
            }
        }
        Badge(st) => match st {
            Status::Enabled => (Some(C::Green), false),
            Status::Partial => (Some(C::Yellow), false),
            Status::Disabled => (Some(C::Red), false),
            Status::NotApplicable => (Some(C::Grey), false),
        },
        Insn(class) => {
            use crate::analyzers::disasm::InsnClass as I;
            match class {
                I::Call => (Some(C::BrightMagenta), true),
                I::Jump => (Some(C::BrightBlue), true),
                I::CondJump => (Some(C::BrightBlue), false),
                I::Ret => (Some(C::Red), true),
                I::Syscall | I::Invalid => (Some(C::Red), false),
                I::Nop => (Some(C::Grey), false),
                I::Stack => (Some(C::Cyan), false),
                I::Compare => (Some(C::Green), false),
                I::Move | I::Arith | I::Logic | I::Other => (None, false),
            }
        }
        // hexyl-style byte classes
        Byte(b) => match b {
            0x00 => (Some(C::Grey), false),
            b' ' | b'\t' | b'\n' | b'\r' => (Some(C::Green), false),
            0x21..=0x7e => (Some(C::Cyan), false),
            0x01..=0x1f | 0x7f => (Some(C::Magenta), false),
            _ => (Some(C::Yellow), false),
        },
        Str => (Some(C::Green), false),
        Spark(e) | Bar(e, _) => paint_of(Entropy(e)),
    }
}

fn owo_style(tone: Tone) -> Style {
    let (c, bold) = paint_of(tone);
    let st = match c {
        None => Style::new(),
        Some(C::Red) => Style::new().red(),
        Some(C::Green) => Style::new().green(),
        Some(C::Yellow) => Style::new().yellow(),
        Some(C::Magenta) => Style::new().magenta(),
        Some(C::Cyan) => Style::new().cyan(),
        Some(C::Grey) => Style::new().bright_black(),
        Some(C::BrightBlue) => Style::new().bright_blue(),
        Some(C::BrightMagenta) => Style::new().bright_magenta(),
    };
    if bold { st.bold() } else { st }
}

fn comfy_color(c: C) -> Color {
    // crossterm's "Dark*" colors are the standard (non-bright) ANSI colors.
    match c {
        C::Red => Color::DarkRed,
        C::Green => Color::DarkGreen,
        C::Yellow => Color::DarkYellow,
        C::Magenta => Color::DarkMagenta,
        C::Cyan => Color::DarkCyan,
        C::Grey => Color::DarkGrey,
        C::BrightBlue => Color::Blue,
        C::BrightMagenta => Color::Magenta,
    }
}

fn glyph(st: Status) -> &'static str {
    match st {
        Status::Enabled => "✓",
        Status::Partial => "~",
        Status::Disabled => "✗",
        Status::NotApplicable => "-",
    }
}

fn bar(e: f64) -> char {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    BARS[(e.clamp(0.0, 7.999) as usize).min(7)]
}

/// What a span looks like on screen, without color.
fn display_text(sp: &Span) -> String {
    match sp.tone {
        Tone::Sep => " · ".to_string(),
        Tone::Badge(st) => format!("{} {}", glyph(st), sanitize(&sp.text)),
        Tone::Entropy(e) => format!("{} {}", sp.text, bar(e)),
        Tone::Spark(e) => bar(e).to_string(),
        Tone::Bar(e, w) => wide_bar(e, usize::from(w)),
        _ => sanitize(&sp.text).into_owned(),
    }
}

/// `e` (0..=8 bits/byte) as a bar of `width` cells with 1/8-cell resolution.
fn wide_bar(e: f64, width: usize) -> String {
    const PARTIAL: [&str; 8] = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
    let eighths = ((e / 8.0).clamp(0.0, 1.0) * (width * 8) as f64).round() as usize;
    let mut s = "█".repeat(eighths / 8);
    s.push_str(PARTIAL[eighths % 8]);
    let used = eighths / 8 + usize::from(!eighths.is_multiple_of(8));
    s.push_str(&" ".repeat(width.saturating_sub(used)));
    s
}

fn paint(text: &str, tone: Tone) -> String {
    if matches!(tone, Tone::Normal | Tone::Num | Tone::Hash) {
        return text.to_string();
    }
    text.style(owo_style(tone)).to_string()
}

fn dim(text: &str) -> String {
    text.bright_black().to_string()
}

pub fn write(doc: &Doc, width: usize, out: &mut String) {
    for block in &doc.blocks {
        match block {
            Block::Panel(p) => panel(p, width, out),
            Block::Heading { title, subtitle } => {
                out.push_str(&title.bold().to_string());
                if let Some(sub) = subtitle {
                    out.push_str(&dim(&format!(" ({})", sanitize(sub))));
                }
                out.push('\n');
            }
            Block::Table(t) => table(t, width, out),
            Block::Note(line) => {
                for sp in line {
                    out.push_str(&paint(&display_text(sp), sp.tone));
                }
                out.push('\n');
            }
            Block::Lines(lines) => {
                for line in lines {
                    for sp in line {
                        out.push_str(&paint(&display_text(sp), sp.tone));
                    }
                    out.push('\n');
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Panels
// ---------------------------------------------------------------------------

fn line_width(line: &Line) -> usize {
    line.iter().map(|sp| display_text(sp).width()).sum()
}

/// Greedy word wrap that keeps badges/separators intact and drops separators
/// and spaces that would start a new line.
fn wrap(line: &Line, width: usize) -> Vec<Vec<(String, Tone)>> {
    let width = width.max(8);
    let mut out: Vec<Vec<(String, Tone)>> = vec![Vec::new()];
    let mut w = 0usize;
    for sp in line {
        let text = display_text(sp);
        let atomic = matches!(sp.tone, Tone::Badge(_) | Tone::Sep);
        let pieces = if atomic {
            vec![text]
        } else {
            split_words(&text)
        };
        for piece in pieces {
            let pw = piece.width();
            let blank = piece.trim().is_empty();
            if w > 0 && w + pw > width {
                // Don't leave a separator or spaces dangling at the end of the line.
                if let Some(cur) = out.last_mut() {
                    while cur
                        .last()
                        .is_some_and(|(t, tone)| *tone == Tone::Sep || t.trim().is_empty())
                    {
                        cur.pop();
                    }
                }
                out.push(Vec::new());
                w = 0;
                if blank || sp.tone == Tone::Sep {
                    continue;
                }
            }
            if w == 0 && blank && !out.last().is_some_and(Vec::is_empty) {
                continue;
            }
            if pw > width {
                for chunk in chunk_by_width(&piece, width) {
                    let cw = chunk.width();
                    if w > 0 && w + cw > width {
                        out.push(Vec::new());
                        w = 0;
                    }
                    w += cw;
                    out.last_mut().expect("non-empty").push((chunk, sp.tone));
                }
                continue;
            }
            w += pw;
            out.last_mut().expect("non-empty").push((piece, sp.tone));
        }
    }
    out
}

fn split_words(t: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut cur_space = None;
    for c in t.chars() {
        let sp = c == ' ';
        if cur_space.is_some_and(|s| s != sp) {
            out.push(std::mem::take(&mut cur));
        }
        cur_space = Some(sp);
        cur.push(c);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn chunk_by_width(t: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut w = 0;
    for c in t.chars() {
        let cw = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if w + cw > width && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
            w = 0;
        }
        cur.push(c);
        w += cw;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn panel(p: &Panel, term_width: usize, out: &mut String) {
    let rows = || p.groups.iter().flat_map(|g| g.rows.iter());
    let key_w = rows().map(|r| r.key.width()).max().unwrap_or(4);
    let natural = rows()
        .flat_map(|r| r.lines.iter())
        .map(line_width)
        .max()
        .unwrap_or(0);
    let title = format!(" {} ", sanitize(&p.title));
    let title_w = title.width();
    let max_inner = term_width.saturating_sub(4).max(40);
    let inner = (key_w + 2 + natural)
        .max(title_w + 4)
        .max(56)
        .min(max_inner);
    let val_w = inner.saturating_sub(key_w + 2).max(8);
    let inner = inner.max(key_w + 2 + val_w);

    let rule = |n: usize| "─".repeat(n);
    out.push_str(&dim("╭─"));
    out.push_str(&title.bold().to_string());
    out.push_str(&dim(&format!(
        "{}╮",
        rule((inner + 1).saturating_sub(title_w))
    )));
    out.push('\n');

    for (gi, g) in p.groups.iter().enumerate() {
        if gi > 0 {
            match &g.title {
                Some(t) => {
                    let t = format!(" {} ", sanitize(t));
                    out.push_str(&dim("├─"));
                    out.push_str(&t.bold().to_string());
                    out.push_str(&dim(&format!(
                        "{}┤",
                        rule((inner + 1).saturating_sub(t.width()))
                    )));
                }
                None => out.push_str(&dim(&format!("├{}┤", rule(inner + 2)))),
            }
            out.push('\n');
        }
        for row in &g.rows {
            let mut first = true;
            for line in &row.lines {
                for wrapped in wrap(line, val_w) {
                    let key = if first { row.key.as_str() } else { "" };
                    first = false;
                    let mut used = 0;
                    let mut body = String::new();
                    for (text, tone) in &wrapped {
                        used += text.width();
                        body.push_str(&paint(text, *tone));
                    }
                    out.push_str(&dim("│ "));
                    let pad_key = key_w.saturating_sub(key.width());
                    out.push_str(&paint(key, Tone::Key));
                    out.push_str(&" ".repeat(pad_key + 2));
                    out.push_str(&body);
                    out.push_str(&" ".repeat(val_w.saturating_sub(used)));
                    out.push_str(&dim(" │"));
                    out.push('\n');
                }
            }
        }
    }
    out.push_str(&dim(&format!("╰{}╯", rule(inner + 2))));
    out.push('\n');
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

fn cell(sp: &Span) -> Cell {
    let (c, bold) = paint_of(sp.tone);
    let mut cell = Cell::new(display_text(sp));
    if let Some(c) = c {
        cell = cell.fg(comfy_color(c));
    }
    if bold {
        cell = cell.add_attribute(Attribute::Bold);
    }
    cell
}

/// Above this many rows comfy-table gets slow (it measures every cell several
/// times); big tables use a simple aligned layout instead.
const COMFY_MAX_ROWS: usize = 2000;

fn fast_table(t: &Table, out: &mut String) {
    let texts: Vec<Vec<String>> = t
        .rows
        .iter()
        .map(|r| r.iter().map(display_text).collect())
        .collect();
    let mut widths: Vec<usize> = t.columns.iter().map(|c| c.name.width()).collect();
    for row in &texts {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.width());
            }
        }
    }
    let pad = |text: &str, i: usize| -> (usize, usize) {
        let fill = widths[i].saturating_sub(text.width());
        match t.columns[i].align {
            Align::Right => (fill, 0),
            Align::Left => (0, if i + 1 == widths.len() { 0 } else { fill }),
        }
    };
    let mut header = String::new();
    for (i, c) in t.columns.iter().enumerate() {
        let (l, r) = pad(&c.name, i);
        header.push_str(&" ".repeat(l));
        header.push_str(&c.name.bold().to_string());
        header.push_str(&" ".repeat(r));
        header.push_str("  ");
    }
    out.push_str(header.trim_end());
    out.push('\n');
    let total: usize = widths.iter().sum::<usize>() + 2 * widths.len().saturating_sub(1);
    out.push_str(&dim(&"─".repeat(total)));
    out.push('\n');
    for (row, cells) in t.rows.iter().zip(&texts) {
        let mut line = String::new();
        for (i, (sp, text)) in row.iter().zip(cells).enumerate() {
            let (l, r) = pad(text, i);
            line.push_str(&" ".repeat(l));
            line.push_str(&paint(text, sp.tone));
            line.push_str(&" ".repeat(r));
            if i + 1 < row.len() {
                line.push_str("  ");
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
}

fn table(t: &Table, width: usize, out: &mut String) {
    if t.rows.len() > COMFY_MAX_ROWS {
        return fast_table(t, out);
    }
    let mut tb = CTable::new();
    tb.load_style(TABLE_STYLE)
        .enforce_styling()
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(width.min(u16::MAX as usize) as u16);
    tb.set_header(
        t.columns
            .iter()
            .map(|c| Cell::new(&c.name).add_attribute(Attribute::Bold)),
    );
    for row in &t.rows {
        tb.add_row(row.iter().map(cell));
    }
    for (i, c) in t.columns.iter().enumerate() {
        if c.align == Align::Right
            && let Some(col) = tb.column_mut(i)
        {
            col.set_cell_alignment(CellAlignment::Right);
        }
    }
    out.push_str(&tb.to_string());
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(lines: &[Vec<(String, Tone)>]) -> Vec<String> {
        lines
            .iter()
            .map(|l| l.iter().map(|(t, _)| t.as_str()).collect::<String>())
            .collect()
    }

    #[test]
    fn wrap_keeps_badges_whole_and_drops_leading_separators() {
        let line = vec![
            Span::new("NX", Tone::Badge(Status::Enabled)),
            Span::new("", Tone::Sep),
            Span::new("RELRO (partial)", Tone::Badge(Status::Partial)),
        ];
        let w = wrap(&line, 20);
        assert_eq!(text(&w), vec!["✓ NX", "~ RELRO (partial)"]);
    }

    #[test]
    fn wrap_splits_words_and_long_tokens() {
        let line = vec![Span::new("alpha beta gamma", Tone::Normal)];
        assert_eq!(text(&wrap(&line, 10)), vec!["alpha beta", "gamma"]);
        let line = vec![Span::new("0123456789abcdef", Tone::Hash)];
        assert_eq!(text(&wrap(&line, 8)), vec!["01234567", "89abcdef"]);
    }
}
