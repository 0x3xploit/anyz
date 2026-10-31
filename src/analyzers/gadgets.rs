//! `--gadgets`: a basic ROP gadget finder. Gadgets end in a return, contain no
//! other control flow, and are deduplicated by their text (lowest address kept).
//!
//! x86 scans every `c3`/`c2` byte (so unintended instructions are found too) and
//! decodes backwards over a bounded window; fixed-width ISAs step back from real
//! return instructions by the instruction alignment.

use std::collections::HashMap;

use anyhow::{Result, bail};
use serde::Serialize;

use super::disasm::{Engine, InsnClass, Syntax, code_chunks};
use super::serialize_hex;
use crate::model::{Arch, Binary};

/// Instructions before the return.
pub const DEFAULT_DEPTH: usize = 4;
const MAX_GADGETS: usize = 50_000;

#[derive(Debug, Clone, Serialize)]
pub struct Gadget {
    pub addr: u64,
    /// `pop rdi ; ret`
    pub text: String,
    pub instructions: usize,
    #[serde(serialize_with = "serialize_hex")]
    pub bytes: Vec<u8>,
    /// Hints: `pop-reg`, `syscall`, `pivot`, `align`.
    pub tags: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GadgetsReport {
    pub arch: String,
    pub depth: usize,
    pub total: usize,
    pub truncated: bool,
    pub gadgets: Vec<Gadget>,
}

struct Insn {
    addr: u64,
    len: usize,
    class: InsnClass,
    text: String,
}

fn decode(engine: &Engine, window: &[u8], addr: u64, limit: usize) -> Vec<Insn> {
    let mut out = Vec::new();
    engine.sweep(window, addr, limit, |d| {
        out.push(Insn {
            addr: d.addr,
            len: d.bytes.len(),
            class: d.class,
            text: if d.operands.is_empty() {
                d.mnemonic.to_string()
            } else {
                format!("{} {}", d.mnemonic, d.operands)
            },
        });
        d.class != InsnClass::Invalid
    });
    out
}

/// A system call that returns to the next instruction (`int 0x80`, `svc #0`),
/// as opposed to breakpoints and other traps the disassembler groups with it.
fn is_syscall(text: &str) -> bool {
    matches!(
        text,
        "syscall" | "sysenter" | "int 0x80" | "int 0x2e" | "ecall"
    ) || text.starts_with("svc ")
        || text.starts_with("swi ")
}

/// Instructions that fault in user mode, so execution never reaches the return.
fn faults(ins: &Insn) -> bool {
    if ins.class == InsnClass::Syscall {
        return !is_syscall(&ins.text);
    }
    let mnemonic = ins.text.split(' ').next().unwrap_or_default();
    matches!(
        mnemonic,
        "ud0" | "ud1" | "ud2" | "udf" | "hlt" | "in" | "out" | "cli" | "sti" | "bkpt"
    ) || (mnemonic.len() == 4 && mnemonic.starts_with("ins"))
        || (mnemonic.len() == 5 && mnemonic.starts_with("outs"))
}

/// A valid gadget is an exact tiling of `window` ending in the return at `ret`.
fn validate(insns: &[Insn], start: u64, ret: u64, end: u64) -> bool {
    let Some(last) = insns.last() else {
        return false;
    };
    if last.addr != ret || last.class != InsnClass::Ret || last.addr + last.len as u64 != end {
        return false;
    }
    let mut at = start;
    for (i, ins) in insns.iter().enumerate() {
        if ins.addr != at {
            return false;
        }
        let last = i + 1 == insns.len();
        if !last
            && (ins.class.is_branch()
                || matches!(ins.class, InsnClass::Ret | InsnClass::Invalid)
                || faults(ins))
        {
            return false;
        }
        at += ins.len as u64;
    }
    true
}

fn tags(insns: &[Insn]) -> Vec<&'static str> {
    let body = &insns[..insns.len() - 1];
    let mut tags = Vec::new();
    if body.is_empty() {
        tags.push("align");
    }
    if !body.is_empty() && body.iter().all(|i| i.text.starts_with("pop ")) {
        tags.push("pop-reg");
    }
    if body.iter().any(|i| is_syscall(&i.text)) {
        tags.push("syscall");
    }
    let pivot = body.iter().any(|i| {
        let t = i.text.as_str();
        t == "leave"
            || t.starts_with("pop rsp")
            || t.starts_with("pop esp")
            || t.starts_with("mov rsp,")
            || t.starts_with("mov esp,")
            || (t.starts_with("xchg") && (t.contains("rsp") || t.contains("esp")))
    });
    if pivot {
        tags.push("pivot");
    }
    tags
}

pub fn analyze(bin: &Binary, depth: usize) -> Result<GadgetsReport> {
    let depth = depth.clamp(1, 16);
    let fixed = match bin.arch {
        Arch::X86 | Arch::X86_64 => false,
        Arch::Arm | Arch::Arm64 | Arch::RiscV32 | Arch::RiscV64 => true,
        ref other => bail!("--gadgets supports x86, x86-64, ARM, ARM64 and RISC-V, not '{other}'"),
    };
    let mut found: Vec<Gadget> = Vec::new();
    let mut by_text: HashMap<String, usize> = HashMap::new();
    let mut total = 0usize;
    let mut engines: [Option<Engine>; 2] = [None, None];
    let mut add = |insns: Vec<Insn>, bytes: &[u8]| {
        let text = insns
            .iter()
            .map(|i| i.text.as_str())
            .collect::<Vec<_>>()
            .join(" ; ");
        let addr = insns[0].addr;
        match by_text.get(&text) {
            Some(&i) => {
                if addr < found[i].addr {
                    found[i].addr = addr;
                }
            }
            None => {
                total += 1;
                if found.len() < MAX_GADGETS {
                    by_text.insert(text.clone(), found.len());
                    found.push(Gadget {
                        addr,
                        instructions: insns.len(),
                        tags: tags(&insns),
                        bytes: bytes.to_vec(),
                        text,
                    });
                }
            }
        }
    };

    for (start, data, thumb, _) in code_chunks(bin) {
        let slot = usize::from(thumb);
        if engines[slot].is_none() {
            engines[slot] = Some(Engine::new(bin, thumb, Syntax::Intel)?);
        }
        let engine = engines[slot].as_ref().expect("engine just created");
        // (offset, length) of every return instruction to build gadgets from.
        let rets: Vec<(usize, usize)> = if fixed {
            let mut v = Vec::new();
            engine.sweep(data, start, usize::MAX, |d| {
                if d.class == InsnClass::Ret {
                    v.push(((d.addr - start) as usize, d.bytes.len()));
                }
                true
            });
            v
        } else {
            memchr::memchr2_iter(0xc3, 0xc2, data)
                .map(|p| (p, if data[p] == 0xc3 { 1 } else { 3 }))
                .filter(|&(p, len)| p + len <= data.len())
                .collect()
        };
        let step = if fixed { engine.align() } else { 1 };
        let max_back = if fixed {
            depth * 4
        } else {
            (depth * 6).min(32)
        };
        for (p, len) in rets {
            let end = p + len;
            let ret_va = start + p as u64;
            let end_va = start + end as u64;
            let mut back = 0;
            while back <= max_back && back <= p {
                let s = p - back;
                let window = &data[s..end];
                let insns = decode(engine, window, start + s as u64, depth + 1);
                if validate(&insns, start + s as u64, ret_va, end_va) {
                    add(insns, window);
                }
                back += step;
            }
        }
    }
    found.sort_by_key(|g| g.addr);
    Ok(GadgetsReport {
        arch: bin.arch.name().to_string(),
        depth,
        total,
        truncated: total > MAX_GADGETS,
        gadgets: found,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(class: InsnClass, text: &str) -> Insn {
        Insn {
            addr: 0,
            len: 1,
            class,
            text: text.into(),
        }
    }

    #[test]
    fn syscalls_versus_traps() {
        for s in ["syscall", "sysenter", "int 0x80", "svc #0", "ecall"] {
            assert!(is_syscall(s), "{s}");
            assert!(!faults(&insn(InsnClass::Syscall, s)), "{s}");
        }
        for s in ["int 0", "int3", "into", "brk #0x3e8", "ebreak"] {
            assert!(!is_syscall(s), "{s}");
            assert!(faults(&insn(InsnClass::Syscall, s)), "{s}");
        }
        for s in [
            "in eax, 0x48",
            "out dx, al",
            "insd",
            "outsb",
            "hlt",
            "ud2",
            "cli",
        ] {
            assert!(faults(&insn(InsnClass::Other, s)), "{s}");
        }
        for s in ["inc eax", "ins v0.s[1], w0", "pop rdi", "mov rax, rdi"] {
            assert!(!faults(&insn(InsnClass::Other, s)), "{s}");
        }
    }
}
