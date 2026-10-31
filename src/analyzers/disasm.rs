//! Disassembly (capstone) annotated with symbols, PLT/stub names, pointer slots
//! and string literals.

use anyhow::{Result, anyhow, bail};
use capstone::arch::{self, ArchOperand};
use capstone::{Capstone, Insn, RegId};
use serde::Serialize;

use super::{Names, serialize_hex};
use crate::addr;
use crate::model::{Arch, Binary, Endian, SymKind};

/// Instructions shown when neither a range, a count nor a sized symbol is given.
pub const DEFAULT_COUNT: usize = 48;
/// Largest range disassembled in one go.
const MAX_BYTES: u64 = 4 << 20;

// capstone's architecture-independent instruction groups (cs_group_type).
const GRP_JUMP: u8 = 1;
const GRP_CALL: u8 = 2;
const GRP_RET: u8 = 3;
const GRP_INT: u8 = 4;
const GRP_IRET: u8 = 5;
const GRP_BRANCH_RELATIVE: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Syntax {
    Intel,
    Att,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InsnClass {
    Call,
    Jump,
    CondJump,
    Ret,
    Syscall,
    Nop,
    Stack,
    Move,
    Arith,
    Logic,
    Compare,
    Other,
    Invalid,
}

impl InsnClass {
    pub fn is_branch(self) -> bool {
        matches!(
            self,
            InsnClass::Call | InsnClass::Jump | InsnClass::CondJump
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RefKind {
    /// Branch / call target.
    Code,
    /// Data address (lea, adrp+add, auipc+addi, literal pool, ...).
    Data,
    /// Indirect branch through a pointer slot (GOT / IAT).
    Slot,
}

#[derive(Debug, Clone, Serialize)]
pub struct Reference {
    pub addr: u64,
    pub kind: RefKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InsnRow {
    pub addr: u64,
    #[serde(serialize_with = "serialize_hex")]
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub class: InsnClass,
    /// Symbol (or stub) that starts at this instruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<Reference>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisasmReport {
    pub arch: String,
    /// Decoder mode: `x86-64`, `thumb`, `rv64gc`, ...
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syntax: Option<Syntax>,
    pub start: u64,
    /// End of the last decoded instruction.
    pub end: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    pub instructions: Vec<InsnRow>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DisasmRequest {
    /// Start address expression; `None` = `main`, else the entry point.
    pub from: Option<String>,
    /// End address expression, or `+LEN`.
    pub to: Option<String>,
    pub count: Option<usize>,
    pub syntax: Option<Syntax>,
    /// Force ARM Thumb mode.
    pub thumb: bool,
}

// ---------------------------------------------------------------------------
// Engine: capstone setup + linear sweep, shared with xrefs/gadgets
// ---------------------------------------------------------------------------

/// One decoded instruction (borrowed from capstone for the callback's duration).
pub(crate) struct Decoded<'i> {
    pub addr: u64,
    pub bytes: &'i [u8],
    pub mnemonic: &'i str,
    pub operands: &'i str,
    pub class: InsnClass,
    pub branch: Option<u64>,
    pub data: Option<(u64, RefKind)>,
}

pub(crate) struct Engine {
    cs: Capstone,
    arch: Arch,
    thumb: bool,
    /// Bytes to skip over an undecodable instruction.
    align: usize,
    /// Treat immediates as possible addresses (non-PIE images).
    imm_refs: bool,
    image: (u64, u64),
    pub mode: String,
}

/// Registers holding a known absolute address (adrp/auipc results).
#[derive(Default)]
struct RegTracker(Vec<(u16, u64)>);

impl RegTracker {
    fn get(&self, r: RegId) -> Option<u64> {
        self.0.iter().find(|(k, _)| *k == r.0).map(|(_, v)| *v)
    }
    fn set(&mut self, r: RegId, v: u64) {
        self.clear(r);
        if self.0.len() > 32 {
            self.0.remove(0);
        }
        self.0.push((r.0, v));
    }
    fn clear(&mut self, r: RegId) {
        self.0.retain(|(k, _)| *k != r.0);
    }
    fn reset(&mut self) {
        self.0.clear();
    }
}

fn first_reg(ops: &[ArchOperand]) -> Option<RegId> {
    match ops.first()? {
        ArchOperand::Arm64Operand(o) => match o.op_type {
            arch::arm64::Arm64OperandType::Reg(r) => Some(r),
            _ => None,
        },
        ArchOperand::RiscVOperand(arch::riscv::RiscVOperand::Reg(r)) => Some(*r),
        _ => None,
    }
}

impl Engine {
    pub(crate) fn new(bin: &Binary, thumb: bool, syntax: Syntax) -> Result<Engine> {
        use arch::*;
        let endian = if bin.endian == Endian::Big {
            capstone::Endian::Big
        } else {
            capstone::Endian::Little
        };
        let x86_syntax = match syntax {
            Syntax::Intel => x86::ArchSyntax::Intel,
            Syntax::Att => x86::ArchSyntax::Att,
        };
        let new = Capstone::new;
        let (cs, mode, align) = match &bin.arch {
            Arch::X86 => (
                new()
                    .x86()
                    .mode(x86::ArchMode::Mode32)
                    .syntax(x86_syntax)
                    .detail(true)
                    .build(),
                "x86",
                1,
            ),
            Arch::X86_64 => (
                new()
                    .x86()
                    .mode(x86::ArchMode::Mode64)
                    .syntax(x86_syntax)
                    .detail(true)
                    .build(),
                "x86-64",
                1,
            ),
            Arch::Arm => {
                let mode = if thumb {
                    arm::ArchMode::Thumb
                } else {
                    arm::ArchMode::Arm
                };
                (
                    new().arm().mode(mode).endian(endian).detail(true).build(),
                    if thumb { "thumb" } else { "arm" },
                    if thumb { 2 } else { 4 },
                )
            }
            Arch::Arm64 => (
                new()
                    .arm64()
                    .mode(arm64::ArchMode::Arm)
                    .endian(endian)
                    .detail(true)
                    .build(),
                "arm64",
                4,
            ),
            Arch::Mips => (
                new()
                    .mips()
                    .mode(mips::ArchMode::Mips32)
                    .endian(endian)
                    .detail(true)
                    .build(),
                "mips32",
                4,
            ),
            Arch::Mips64 => (
                new()
                    .mips()
                    .mode(mips::ArchMode::Mips64)
                    .endian(endian)
                    .detail(true)
                    .build(),
                "mips64",
                4,
            ),
            Arch::RiscV32 => (
                new()
                    .riscv()
                    .mode(riscv::ArchMode::RiscV32)
                    .extra_mode([riscv::ArchExtraMode::RiscVC].into_iter())
                    .detail(true)
                    .build(),
                "rv32gc",
                2,
            ),
            Arch::RiscV64 => (
                new()
                    .riscv()
                    .mode(riscv::ArchMode::RiscV64)
                    .extra_mode([riscv::ArchExtraMode::RiscVC].into_iter())
                    .detail(true)
                    .build(),
                "rv64gc",
                2,
            ),
            Arch::PowerPc => (
                new()
                    .ppc()
                    .mode(ppc::ArchMode::Mode32)
                    .endian(endian)
                    .detail(true)
                    .build(),
                "ppc32",
                4,
            ),
            Arch::PowerPc64 => (
                new()
                    .ppc()
                    .mode(ppc::ArchMode::Mode64)
                    .endian(endian)
                    .detail(true)
                    .build(),
                "ppc64",
                4,
            ),
            Arch::Sparc => (
                new()
                    .sparc()
                    .mode(sparc::ArchMode::Default)
                    .detail(true)
                    .build(),
                "sparc",
                4,
            ),
            Arch::Sparc64 => (
                new().sparc().mode(sparc::ArchMode::V9).detail(true).build(),
                "sparcv9",
                4,
            ),
            Arch::S390x => (
                new()
                    .sysz()
                    .mode(sysz::ArchMode::Default)
                    .detail(true)
                    .build(),
                "s390x",
                2,
            ),
            Arch::M68k => (
                new()
                    .m68k()
                    .mode(m68k::ArchMode::M68k040)
                    .detail(true)
                    .build(),
                "m68k",
                2,
            ),
            other => bail!(
                "disassembly is not supported for architecture '{other}'{}",
                if other.is_unknown() {
                    " (pass --arch for raw blobs)"
                } else {
                    ""
                }
            ),
        };
        let cs = cs.map_err(|e| anyhow!("cannot initialise the disassembler: {e}"))?;
        let lo = bin.regions.iter().map(|r| r.va).min().unwrap_or(0);
        let hi = bin
            .regions
            .iter()
            .map(|r| r.va.saturating_add(r.vsize))
            .max()
            .unwrap_or(0);
        Ok(Engine {
            cs,
            arch: bin.arch.clone(),
            thumb,
            align,
            imm_refs: bin.image_base >= 0x10000,
            image: (lo, hi),
            mode: mode.to_string(),
        })
    }

    /// Linear sweep over `code` loaded at `start`, at most `limit` instructions.
    /// Undecodable bytes are reported as `(bad)` and skipped. The callback
    /// returns `false` to stop. Returns the number of bytes consumed.
    pub(crate) fn sweep(
        &self,
        code: &[u8],
        start: u64,
        limit: usize,
        mut f: impl FnMut(Decoded<'_>) -> bool,
    ) -> usize {
        let mut pos = 0usize;
        let mut count = 0usize;
        let mut regs = RegTracker::default();
        while pos < code.len() && count < limit {
            let Ok(mut iter) = self.cs.disasm_iter(&code[pos..], start + pos as u64) else {
                break;
            };
            while let Some(insn) = iter.next() {
                let d = self.decode(&insn, &mut regs);
                pos += insn.len();
                count += 1;
                if !f(d) || count >= limit {
                    return pos;
                }
            }
            if pos >= code.len() {
                break;
            }
            let n = self.align.min(code.len() - pos);
            let bad = Decoded {
                addr: start + pos as u64,
                bytes: &code[pos..pos + n],
                mnemonic: "(bad)",
                operands: "",
                class: InsnClass::Invalid,
                branch: None,
                data: None,
            };
            pos += n;
            count += 1;
            regs.reset();
            if !f(bad) {
                break;
            }
        }
        pos
    }

    fn decode<'i>(&self, insn: &'i Insn<'_>, regs: &mut RegTracker) -> Decoded<'i> {
        let mnemonic = insn.mnemonic().unwrap_or("?");
        let operands = insn.op_str().unwrap_or("");
        let detail = self.cs.insn_detail(insn).ok();
        let groups: Vec<u8> = detail
            .as_ref()
            .map(|d| d.groups().iter().map(|g| g.0).collect())
            .unwrap_or_default();
        let class = classify(&self.arch, &groups, mnemonic, operands);
        // capstone-rs transmutes ARM64 mrs/msr system-register numbers into an
        // enum, which is undefined behaviour for values it does not know (seen
        // on fuzzed input). Those instructions never carry code/data references.
        let sysreg = self.arch == Arch::Arm64 && matches!(mnemonic, "mrs" | "msr");
        let ops = match &detail {
            Some(d) if !sysreg => d.arch_detail().operands(),
            _ => Vec::new(),
        };
        let (branch, data) = self.references(insn, mnemonic, class, &ops, regs);
        if class.is_branch() || class == InsnClass::Ret {
            regs.reset();
        }
        Decoded {
            addr: insn.address(),
            bytes: insn.bytes(),
            mnemonic,
            operands,
            class,
            branch,
            data,
        }
    }

    /// Bytes per instruction step (1 for x86, 2 for Thumb/RVC, 4 otherwise).
    pub(crate) fn align(&self) -> usize {
        self.align
    }

    fn plausible(&self, v: u64) -> bool {
        v >= self.image.0 && v < self.image.1
    }

    fn references(
        &self,
        insn: &Insn<'_>,
        m: &str,
        class: InsnClass,
        ops: &[ArchOperand],
        regs: &mut RegTracker,
    ) -> (Option<u64>, Option<(u64, RefKind)>) {
        use arch::x86::X86OperandType;
        let pc = insn.address();
        let next = pc + insn.len() as u64;
        let branch = class.is_branch();
        let mut target = None;
        let mut data = None;
        match self.arch {
            Arch::X86 | Arch::X86_64 => {
                let mask = if self.arch == Arch::X86 {
                    0xffff_ffff
                } else {
                    u64::MAX
                };
                let rip = RegId(arch::x86::X86Reg::X86_REG_RIP as u16);
                for op in ops {
                    let ArchOperand::X86Operand(o) = op else {
                        continue;
                    };
                    match &o.op_type {
                        X86OperandType::Imm(v) => {
                            let v = *v as u64 & mask;
                            if branch {
                                target = Some(v);
                            } else if self.imm_refs && data.is_none() && self.plausible(v) {
                                data = Some((v, RefKind::Data));
                            }
                        }
                        X86OperandType::Mem(mem) => {
                            let t = if mem.base() == rip {
                                Some(next.wrapping_add_signed(mem.disp()))
                            } else if mem.base().0 == 0
                                && mem.index().0 == 0
                                && mem.segment().0 == 0
                            {
                                Some(mem.disp() as u64 & mask)
                            } else {
                                None
                            };
                            if let Some(t) = t {
                                data =
                                    Some((t, if branch { RefKind::Slot } else { RefKind::Data }));
                            }
                        }
                        _ => {}
                    }
                }
            }
            Arch::Arm64 => {
                use arch::arm64::Arm64OperandType as T;
                for op in ops {
                    if let ArchOperand::Arm64Operand(o) = op
                        && let T::Imm(v) = o.op_type
                        && branch
                    {
                        target = Some(v as u64);
                    }
                }
                let imm = |i: usize| match ops.get(i) {
                    Some(ArchOperand::Arm64Operand(o)) => match o.op_type {
                        T::Imm(v) => Some(v),
                        _ => None,
                    },
                    _ => None,
                };
                let reg = |i: usize| match ops.get(i) {
                    Some(ArchOperand::Arm64Operand(o)) => match o.op_type {
                        T::Reg(r) => Some(r),
                        _ => None,
                    },
                    _ => None,
                };
                let mem = ops.iter().find_map(|op| match op {
                    ArchOperand::Arm64Operand(o) => match &o.op_type {
                        T::Mem(mm) => Some((mm.base(), i64::from(mm.disp()))),
                        _ => None,
                    },
                    _ => None,
                });
                match m {
                    "adrp" => {
                        if let (Some(rd), Some(page)) = (reg(0), imm(1)) {
                            regs.set(rd, page as u64);
                        }
                    }
                    "adr" => {
                        if let Some(v) = imm(1) {
                            data = Some((v as u64, RefKind::Data));
                        }
                    }
                    "add" => {
                        if let (Some(rd), Some(rn), Some(v)) = (reg(0), reg(1), imm(2)) {
                            if let Some(page) = regs.get(rn) {
                                let t = page.wrapping_add_signed(v);
                                data = Some((t, RefKind::Data));
                                regs.set(rd, t);
                            } else {
                                regs.clear(rd);
                            }
                        }
                    }
                    _ if m.starts_with("ld") || m.starts_with("st") => {
                        if let Some((base, disp)) = mem {
                            if let Some(page) = regs.get(base) {
                                data = Some((page.wrapping_add_signed(disp), RefKind::Data));
                            }
                        } else if let Some(v) = imm(1) {
                            data = Some((v as u64, RefKind::Data)); // ldr xN, =literal
                        }
                        if m.starts_with("ld")
                            && let Some(rd) = first_reg(ops)
                        {
                            regs.clear(rd);
                        }
                    }
                    _ => {
                        if let Some(rd) = first_reg(ops) {
                            regs.clear(rd);
                        }
                    }
                }
            }
            Arch::RiscV32 | Arch::RiscV64 => {
                use arch::riscv::RiscVOperand as T;
                let imm = |i: usize| match ops.get(i) {
                    Some(ArchOperand::RiscVOperand(T::Imm(v))) => Some(*v),
                    _ => None,
                };
                let reg = |i: usize| match ops.get(i) {
                    Some(ArchOperand::RiscVOperand(T::Reg(r))) => Some(*r),
                    _ => None,
                };
                let mem = ops.iter().find_map(|op| match op {
                    ArchOperand::RiscVOperand(T::Mem(mm)) => Some((mm.base(), mm.disp())),
                    _ => None,
                });
                if branch {
                    // capstone gives the pc-relative offset for jal/branches.
                    let last = ops.iter().rev().find_map(|op| match op {
                        ArchOperand::RiscVOperand(T::Imm(v)) => Some(*v),
                        _ => None,
                    });
                    if let Some(off) = last {
                        target = Some(pc.wrapping_add_signed(off));
                    } else if let Some((base, disp)) = mem
                        && let Some(v) = regs.get(base)
                    {
                        target = Some(v.wrapping_add_signed(disp)); // auipc + jalr
                    }
                }
                match m {
                    "auipc" => {
                        if let (Some(rd), Some(hi)) = (reg(0), imm(1)) {
                            regs.set(rd, pc.wrapping_add_signed(hi << 12));
                        }
                    }
                    "addi" | "addiw" => {
                        if let (Some(rd), Some(rs), Some(lo)) = (reg(0), reg(1), imm(2)) {
                            if let Some(v) = regs.get(rs) {
                                let t = v.wrapping_add_signed(lo);
                                data = Some((t, RefKind::Data));
                                regs.set(rd, t);
                            } else {
                                regs.clear(rd);
                            }
                        }
                    }
                    _ if !branch => {
                        if let Some((base, disp)) = mem
                            && let Some(v) = regs.get(base)
                        {
                            data = Some((v.wrapping_add_signed(disp), RefKind::Data));
                        }
                        if let Some(rd) = first_reg(ops)
                            && (!m.starts_with('s') || mem.is_none())
                        {
                            regs.clear(rd);
                        }
                    }
                    _ => {}
                }
            }
            Arch::Arm => {
                use arch::arm::ArmOperandType as T;
                let pcreg = RegId(arch::arm::ArmReg::ARM_REG_PC as u16);
                for op in ops {
                    let ArchOperand::ArmOperand(o) = op else {
                        continue;
                    };
                    match &o.op_type {
                        T::Imm(v) if branch => target = Some(u64::from(*v as u32)),
                        T::Mem(mm) if mm.base() == pcreg && !branch => {
                            // ldr rX, [pc, #imm]: literal pool; report the pointer it holds.
                            let base = (pc + if self.thumb { 4 } else { 8 }) & !3;
                            let lit = base.wrapping_add_signed(i64::from(mm.disp()));
                            data = Some((lit, RefKind::Data));
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                if branch {
                    target = ops.iter().rev().find_map(|op| match op {
                        ArchOperand::MipsOperand(arch::mips::MipsOperand::Imm(v)) => {
                            Some(*v as u64)
                        }
                        ArchOperand::PpcOperand(arch::ppc::PpcOperand::Imm(v)) => Some(*v as u64),
                        ArchOperand::SparcOperand(arch::sparc::SparcOperand::Imm(v)) => {
                            Some(*v as u64)
                        }
                        _ => None,
                    });
                }
            }
        }
        (target, data)
    }
}

/// A run of code to sweep: (start VA, bytes, thumb, label).
pub(crate) type Chunk<'a> = (u64, &'a [u8], bool, String);

/// Executable code, split by ARM mapping symbols ($a/$t/$d) where present.
pub(crate) fn code_chunks(bin: &Binary) -> Vec<Chunk<'_>> {
    let mut chunks = Vec::new();
    let mapping = bin.elf().map(|e| e.arm_mapping.as_slice()).unwrap_or(&[]);
    for s in bin
        .sections
        .iter()
        .filter(|s| s.alloc && s.perms.x && s.file_size > 0)
    {
        let data = bin.section_data(s);
        let end = s.addr + data.len() as u64;
        let name = s.full_name();
        if bin.arch != Arch::Arm || mapping.is_empty() {
            chunks.push((s.addr, data, bin.thumb, name));
            continue;
        }
        // Mode at the section start, then switch at each mapping symbol.
        let mut mode = mapping
            .iter()
            .rev()
            .find(|(a, _)| *a <= s.addr)
            .map_or(if bin.thumb { 't' } else { 'a' }, |(_, k)| *k);
        let mut cur = s.addr;
        for &(at, kind) in mapping.iter().filter(|(a, _)| *a > s.addr && *a < end) {
            if mode != 'd' && at > cur {
                let (lo, hi) = ((cur - s.addr) as usize, (at - s.addr) as usize);
                chunks.push((cur, &data[lo..hi], mode == 't', name.clone()));
            }
            cur = at;
            mode = kind;
        }
        if mode != 'd' && cur < end {
            chunks.push((
                cur,
                &data[(cur - s.addr) as usize..],
                mode == 't',
                name.clone(),
            ));
        }
    }
    if chunks.is_empty() {
        // No section headers (sstrip'd / packed): fall back to executable mappings.
        for r in bin.regions.iter().filter(|r| r.perms.x && r.file_size > 0) {
            let data = crate::model::clamp_slice(bin.bytes(), r.offset, r.file_size);
            chunks.push((r.va, data, bin.thumb, r.name.clone()));
        }
    }
    chunks
}

const UNCONDITIONAL: &[&str] = &[
    "jmp", "ljmp", "b", "b.w", "bx", "br", "j", "jr", "braa", "brab", "braaz", "brabz", "c.j",
    "c.jr",
];

fn classify(arch: &Arch, groups: &[u8], m: &str, op: &str) -> InsnClass {
    use InsnClass::*;
    let has = |g: u8| groups.contains(&g);
    if has(GRP_CALL) {
        return Call;
    }
    if has(GRP_RET) || has(GRP_IRET) {
        return Ret;
    }
    let ret = match arch {
        Arch::Arm => {
            (m == "bx" && op == "lr")
                || ((m.starts_with("pop") || m.starts_with("ldm")) && op.contains("pc"))
        }
        Arch::Mips | Arch::Mips64 => m == "jr" && op.contains("ra"),
        Arch::RiscV32 | Arch::RiscV64 => {
            m == "ret" || (m == "jr" && op == "ra") || m == "c.jr" && op == "ra"
        }
        _ => false,
    };
    if ret {
        return Ret;
    }
    if has(GRP_INT) {
        return Syscall;
    }
    if has(GRP_JUMP) || has(GRP_BRANCH_RELATIVE) {
        return if UNCONDITIONAL.contains(&m) {
            Jump
        } else {
            CondJump
        };
    }
    let starts = |prefixes: &[&str]| prefixes.iter().any(|p| m.starts_with(p));
    if matches!(
        m,
        "syscall"
            | "sysenter"
            | "int"
            | "int3"
            | "into"
            | "svc"
            | "swi"
            | "ecall"
            | "ebreak"
            | "brk"
            | "hvc"
            | "smc"
    ) {
        Syscall
    } else if starts(&["nop", "endbr", "fnop", "pause"]) || matches!(m, "hint" | "bti" | "c.nop") {
        Nop
    } else if starts(&["push", "pop"])
        || matches!(m, "enter" | "leave")
        || (matches!(m, "stp" | "ldp") && op.contains("sp"))
    {
        Stack
    } else if starts(&[
        "cmp", "test", "tst", "cmn", "teq", "ucomis", "comis", "fcmp", "fucom", "slt", "sgt",
    ]) {
        Compare
    } else if starts(&[
        "and", "or", "xor", "not", "eor", "orr", "bic", "shl", "shr", "sar", "sal", "rol", "ror",
        "rcl", "rcr", "lsl", "lsr", "asr", "sll", "srl", "sra", "bt", "bsf", "bsr", "tzcnt",
        "lzcnt", "popcnt", "pand", "por", "pxor", "c.and", "c.or", "c.xor",
    ]) {
        Logic
    } else if starts(&[
        "add", "sub", "mul", "imul", "div", "idiv", "inc", "dec", "neg", "adc", "sbb", "madd",
        "msub", "udiv", "sdiv", "fadd", "fsub", "fmul", "fdiv", "rem", "smul", "umul", "c.add",
        "c.sub", "padd", "psub",
    ]) {
        Arith
    } else if starts(&[
        "mov", "lea", "ldr", "str", "ld", "st", "lw", "sw", "lb", "sb", "lh", "sh", "li", "la",
        "lui", "auipc", "adr", "cmov", "xchg", "cvt", "lods", "stos", "movs", "cbw", "cwd", "cdq",
        "cqo", "bswap", "rev", "c.l", "c.s", "c.mv",
    ]) {
        Move
    } else {
        Other
    }
}

// ---------------------------------------------------------------------------
// The --disasm view
// ---------------------------------------------------------------------------

fn arm_thumb_at(bin: &Binary, va: u64) -> Option<bool> {
    let map = &bin.elf()?.arm_mapping;
    let i = map.partition_point(|(a, _)| *a <= va);
    map.get(i.checked_sub(1)?).and_then(|(_, kind)| match kind {
        't' => Some(true),
        'a' => Some(false),
        _ => None,
    })
}

/// `main` if there is one, else the entry point.
fn default_start(bin: &Binary) -> Result<(u64, Option<addr::NamedSymbol>)> {
    if let Ok(loc) = addr::resolve(bin, "main")
        && let Some(va) = loc.va
    {
        return Ok((va, loc.symbol));
    }
    bin.entry.map(|e| (e, None)).ok_or_else(|| {
        anyhow!("no main symbol and no entry point; pass an address, e.g. --disasm 0x401000")
    })
}

pub fn analyze(bin: &Binary, req: &DisasmRequest) -> Result<DisasmReport> {
    if bin.arch.is_unknown() {
        bail!(
            "the architecture of this file is unknown; pass --arch <ARCH> (and --base <ADDR>) \
             to disassemble a raw blob, e.g. --arch x86-64"
        );
    }
    let names = Names::new(bin);
    let (mut start, named) = match &req.from {
        Some(expr) => {
            let loc = addr::resolve(bin, expr)?;
            (loc.require_mapped_va(bin)?, loc.symbol)
        }
        None => default_start(bin)?,
    };
    let arm = bin.arch == Arch::Arm;
    let thumb = arm
        && (req.thumb
            || start & 1 == 1
            || named.as_ref().is_some_and(|s| s.thumb)
            || arm_thumb_at(bin, start & !1).unwrap_or(bin.thumb));
    if arm {
        start &= !1;
    }
    let region_end = bin
        .region_for_va(start)
        .map(|r| r.va + r.file_size)
        .ok_or_else(|| anyhow!("{start:#x} is not inside any mapped section or segment"))?;

    let mut notes = Vec::new();
    let (end, limit) = if let Some(to) = &req.to {
        let end = match to.strip_prefix('+') {
            Some(len) => {
                let len =
                    addr::parse_number(len).ok_or_else(|| anyhow!("invalid length '{to}'"))?;
                start
                    .checked_add(len)
                    .ok_or_else(|| anyhow!("range overflows"))?
            }
            None => addr::resolve(bin, to)?.require_va(bin)?,
        };
        if end <= start {
            bail!("end address {end:#x} is not after the start address {start:#x}");
        }
        (end, req.count.unwrap_or(usize::MAX))
    } else if let Some(n) = req.count {
        (region_end, n.max(1))
    } else if let Some(sym) = named.as_ref().filter(|s| {
        s.size > 0 && matches!(s.kind, SymKind::Func | SymKind::NoType | SymKind::Ifunc)
    }) {
        (start.saturating_add(sym.size), usize::MAX)
    } else {
        (region_end, DEFAULT_COUNT)
    };
    // `region_end` is below `start` when start lies in zero-filled memory (.bss).
    let mut len = end.saturating_sub(start);
    if len > MAX_BYTES {
        notes.push(format!("range truncated to {} MiB", MAX_BYTES >> 20));
        len = MAX_BYTES;
    }
    let code = bin
        .bytes_at_va(start, len)
        .map_err(|e| anyhow!("cannot disassemble at {start:#x}: {e}"))?;
    if code.is_empty() {
        bail!("no file-backed bytes at {start:#x}");
    }
    if (code.len() as u64) < len && end != region_end {
        notes.push(format!(
            "stopped after {:#x} bytes: end of the file-backed data at {start:#x}",
            code.len()
        ));
    }

    let syntax = req.syntax.unwrap_or(Syntax::Intel);
    let engine = Engine::new(bin, thumb, syntax)?;
    let mut rows = Vec::new();
    engine.sweep(code, start, limit, |d| {
        rows.push(row(&names, &d));
        true
    });
    let last_end = rows.last().map_or(start, |r| r.addr + r.bytes.len() as u64);
    Ok(DisasmReport {
        arch: bin.arch.name().to_string(),
        mode: engine.mode.clone(),
        syntax: matches!(bin.arch, Arch::X86 | Arch::X86_64).then_some(syntax),
        start,
        end: last_end,
        function: named
            .map(|s| s.name)
            .or_else(|| names.describe(start))
            .or_else(|| (bin.entry == Some(start)).then(|| "entry".to_string())),
        instructions: rows,
        notes,
    })
}

fn row(names: &Names<'_>, d: &Decoded<'_>) -> InsnRow {
    let reference = d
        .branch
        .map(|t| Reference {
            addr: t,
            kind: RefKind::Code,
            name: names.describe_code(t),
            string: None,
        })
        .or_else(|| {
            d.data.map(|(t, kind)| {
                let name = match kind {
                    RefKind::Slot => names
                        .slot(t)
                        .map(str::to_string)
                        .or_else(|| names.describe(t)),
                    _ => names.describe(t),
                };
                // A pointer to a known function is not a string.
                let string = match &name {
                    Some(n) if !n.contains('+') => None,
                    _ if kind == RefKind::Data => names.string_at(t),
                    _ => None,
                };
                Reference {
                    addr: t,
                    kind,
                    name,
                    string,
                }
            })
        });
    InsnRow {
        addr: d.addr,
        bytes: d.bytes.to_vec(),
        mnemonic: d.mnemonic.to_string(),
        operands: d.operands.to_string(),
        class: d.class,
        label: names.exact(d.addr),
        reference,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        use InsnClass::*;
        let x = Arch::X86_64;
        assert_eq!(classify(&x, &[GRP_CALL], "call", "0x401136"), Call);
        assert_eq!(classify(&x, &[GRP_JUMP], "jmp", "0x10"), Jump);
        assert_eq!(classify(&x, &[GRP_JUMP], "je", "0x10"), CondJump);
        assert_eq!(classify(&x, &[GRP_RET], "ret", ""), Ret);
        assert_eq!(classify(&x, &[GRP_INT], "syscall", ""), Syscall);
        assert_eq!(classify(&x, &[], "push", "rbp"), Stack);
        assert_eq!(classify(&x, &[], "mov", "rbp, rsp"), Move);
        assert_eq!(classify(&x, &[], "lea", "rdi, [rip]"), Move);
        assert_eq!(classify(&x, &[], "xor", "eax, eax"), Logic);
        assert_eq!(classify(&x, &[], "shl", "eax, 2"), Logic);
        assert_eq!(classify(&x, &[], "sub", "rsp, 0x40"), Arith);
        assert_eq!(classify(&x, &[], "cmp", "eax, 1"), Compare);
        assert_eq!(classify(&x, &[], "endbr64", ""), Nop);
        assert_eq!(classify(&Arch::Arm, &[GRP_JUMP], "bx", "lr"), Ret);
        assert_eq!(classify(&Arch::Arm, &[], "pop", "{r4, pc}"), Ret);
        assert_eq!(
            classify(&Arch::Arm64, &[GRP_JUMP], "cbz", "x0, 0x10"),
            CondJump
        );
        assert_eq!(
            classify(&Arch::Arm64, &[], "stp", "x29, x30, [sp, #-0x10]!"),
            Stack
        );
    }
}
