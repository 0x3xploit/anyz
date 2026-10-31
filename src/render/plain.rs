//! Plain backend: no colors, ASCII only, one record per line (grep/awk friendly).
//! Used for `--no-color`, `NO_COLOR`, and whenever stdout is not a terminal.

use std::borrow::Cow;

use super::{Align, Block, Doc, Line, Panel, Span, Table, Tone, push_spaces, sanitize, text_width};
use crate::analyzers::checksec::Status;

fn glyph(st: Status) -> &'static str {
    match st {
        Status::Enabled => "[+]",
        Status::Partial => "[~]",
        Status::Disabled => "[-]",
        Status::NotApplicable => "[ ]",
    }
}

fn text(sp: &Span) -> String {
    match sp.tone {
        Tone::Sep => ", ".to_string(),
        Tone::Badge(st) => format!("{} {}", glyph(st), sanitize(&sp.text)),
        Tone::Spark(e) => {
            const RAMP: &[u8] = b" .:-=+*#%@";
            let i = ((e / 8.0).clamp(0.0, 1.0) * (RAMP.len() - 1) as f64).round() as usize;
            char::from(RAMP[i]).to_string()
        }
        Tone::Bar(e, w) => "#".repeat(((e / 8.0).clamp(0.0, 1.0) * f64::from(w)).round() as usize),
        _ => sanitize(&sp.text).into_owned(),
    }
}

fn line_text(line: &Line) -> String {
    line.iter().map(text).collect()
}

pub fn write(doc: &Doc, out: &mut String) {
    for block in &doc.blocks {
        match block {
            Block::Panel(p) => panel(p, out),
            Block::Heading { title, subtitle } => {
                out.push_str(title);
                if let Some(sub) = subtitle {
                    out.push_str(&format!(" ({})", sanitize(sub)));
                }
                out.push('\n');
            }
            Block::Table(t) => table(t, out),
            Block::Note(line) => {
                out.push_str(&line_text(line));
                out.push('\n');
            }
            Block::Lines(lines) => {
                for line in lines {
                    out.push_str(line_text(line).trim_end());
                    out.push('\n');
                }
            }
        }
    }
}

fn panel(p: &Panel, out: &mut String) {
    let key_w = p
        .groups
        .iter()
        .flat_map(|g| g.rows.iter())
        .map(|r| r.key.len())
        .max()
        .unwrap_or(4);
    for (gi, g) in p.groups.iter().enumerate() {
        if gi > 0 {
            out.push('\n');
        }
        if let Some(t) = &g.title {
            out.push_str(&format!("[{t}]\n"));
        }
        for row in &g.rows {
            for (i, line) in row.lines.iter().enumerate() {
                let key = if i == 0 { row.key.as_str() } else { "" };
                let body = line_text(line);
                let l = format!("{key:<key_w$}  {body}");
                out.push_str(l.trim_end());
                out.push('\n');
            }
        }
    }
}

/// Cell text without allocating for the common (already clean) case.
fn cell(sp: &Span) -> Cow<'_, str> {
    match sp.tone {
        Tone::Sep | Tone::Badge(_) | Tone::Spark(_) | Tone::Bar(..) => Cow::Owned(text(sp)),
        _ => sanitize(&sp.text),
    }
}

/// Aligned columns separated by two spaces, header on the first line, no borders.
fn table(t: &Table, out: &mut String) {
    let texts: Vec<Vec<Cow<'_, str>>> = t
        .rows
        .iter()
        .map(|r| r.iter().map(cell).collect())
        .collect();
    let mut widths: Vec<usize> = t.columns.iter().map(|c| text_width(&c.name)).collect();
    for row in &texts {
        for (i, c) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(text_width(c));
            }
        }
    }
    out.reserve(texts.len() * (widths.iter().sum::<usize>() + 2 * widths.len() + 1));
    let last = widths.len().saturating_sub(1);
    let mut emit = |cells: &mut dyn Iterator<Item = &str>| {
        let mut pending = 0usize;
        for (i, c) in cells.enumerate() {
            let fill = widths[i].saturating_sub(text_width(c));
            let right = t.columns[i].align == Align::Right;
            let lead = if right { fill } else { 0 };
            if !c.is_empty() || lead > 0 {
                push_spaces(out, pending + lead);
                pending = 0;
                out.push_str(c);
            } else {
                pending += lead;
            }
            if i < last {
                pending += if right { 0 } else { fill } + 2;
            }
        }
        out.push('\n');
    };
    emit(&mut t.columns.iter().map(|c| c.name.as_str()));
    for row in &texts {
        emit(&mut row.iter().map(|c| c.as_ref()));
    }
}
