use std::io;

use crate::{debug_info::TdbDebugInfo, syscall::get_regs};

#[derive(Debug, Clone)]
pub enum Register {
    R15,
    R14,
    R13,
    R12,
    R11,
    R10,
    R9,
    R8,
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    Rip,
    Eflags,
    OrigRax,
    Cs,
    Ds,
    Es,
    Fs,
    Gs,
    Ss,
}

impl Register {
    pub fn parse(s: &str) -> Result<Register, Box<dyn std::error::Error>> {
        if s.is_empty() {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty string",
            )));
        }
        let bytes = s.as_bytes();
        if bytes[0] != b'$' {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "register should start $ mark",
            )));
        }
        let reg = bytes[1..].iter().map(|c| *c as char).collect::<String>();
        let reg = match reg.as_str() {
            "r15" => Register::R15,
            "r14" => Register::R14,
            "r13" => Register::R13,
            "r12" => Register::R12,
            "r11" => Register::R11,
            "r10" => Register::R10,
            "r9" => Register::R9,
            "r8" => Register::R8,
            "rax" => Register::Rax,
            "rbx" => Register::Rbx,
            "rcx" => Register::Rcx,
            "rdx" => Register::Rdx,
            "rsi" => Register::Rsi,
            "rdi" => Register::Rdi,
            "rbp" => Register::Rbp,
            "rsp" => Register::Rsp,
            "rip" => Register::Rip,
            "eflags" => Register::Eflags,
            "orig_rax" => Register::OrigRax,
            "cs" => Register::Cs,
            "ds" => Register::Ds,
            "es" => Register::Es,
            "fs" => Register::Fs,
            "gs" => Register::Gs,
            "ss" => Register::Ss,
            _ => {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid register name",
                )))
            }
        };
        Ok(reg)
    }

    pub fn get_value(&self, debug_info: &TdbDebugInfo) -> u64 {
        let regs = get_regs(debug_info.target_pid);
        match self {
            Register::R15 => regs.r15,
            Register::R14 => regs.r14,
            Register::R13 => regs.r13,
            Register::R12 => regs.r12,
            Register::R11 => regs.r11,
            Register::R10 => regs.r10,
            Register::R9 => regs.r9,
            Register::R8 => regs.r8,
            Register::Rax => regs.rax,
            Register::Rbx => regs.rbx,
            Register::Rcx => regs.rcx,
            Register::Rdx => regs.rdx,
            Register::Rdi => regs.rdi,
            Register::Rsi => regs.rsi,
            Register::Rbp => regs.rbp,
            Register::Rsp => regs.rsp,
            Register::Rip => regs.rip,
            Register::Eflags => regs.eflags,
            Register::OrigRax => regs.orig_rax,
            Register::Cs => regs.cs,
            Register::Ds => regs.ds,
            Register::Es => regs.es,
            Register::Fs => regs.fs,
            Register::Gs => regs.gs,
            Register::Ss => regs.ss,
        }
    }
}
