use crate::syscall::get_regs;
use nix::unistd::Pid;
use std::io;

#[derive(Debug, Clone, Copy)]
pub enum RegisterType {
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

impl RegisterType {
    pub fn parse(s: &str) -> Result<RegisterType, Box<dyn std::error::Error>> {
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
        let reg_type = match reg.as_str() {
            "r15" => RegisterType::R15,
            "r14" => RegisterType::R14,
            "r13" => RegisterType::R13,
            "r12" => RegisterType::R12,
            "r11" => RegisterType::R11,
            "r10" => RegisterType::R10,
            "r9" => RegisterType::R9,
            "r8" => RegisterType::R8,
            "rax" => RegisterType::Rax,
            "rbx" => RegisterType::Rbx,
            "rcx" => RegisterType::Rcx,
            "rdx" => RegisterType::Rdx,
            "rsi" => RegisterType::Rsi,
            "rdi" => RegisterType::Rdi,
            "rbp" => RegisterType::Rbp,
            "rsp" => RegisterType::Rsp,
            "rip" => RegisterType::Rip,
            "eflags" => RegisterType::Eflags,
            "orig_rax" => RegisterType::OrigRax,
            "cs" => RegisterType::Cs,
            "ds" => RegisterType::Ds,
            "es" => RegisterType::Es,
            "fs" => RegisterType::Fs,
            "gs" => RegisterType::Gs,
            "ss" => RegisterType::Ss,
            _ => {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid register name",
                )))
            }
        };
        Ok(reg_type)
    }

    pub fn get_current_value(&self, pid: Pid) -> u64 {
        let regs = get_regs(pid);
        match self {
            RegisterType::R15 => regs.r15,
            RegisterType::R14 => regs.r14,
            RegisterType::R13 => regs.r13,
            RegisterType::R12 => regs.r12,
            RegisterType::R11 => regs.r11,
            RegisterType::R10 => regs.r10,
            RegisterType::R9 => regs.r9,
            RegisterType::R8 => regs.r8,
            RegisterType::Rax => regs.rax,
            RegisterType::Rbx => regs.rbx,
            RegisterType::Rcx => regs.rcx,
            RegisterType::Rdx => regs.rdx,
            RegisterType::Rdi => regs.rdi,
            RegisterType::Rsi => regs.rsi,
            RegisterType::Rbp => regs.rbp,
            RegisterType::Rsp => regs.rsp,
            RegisterType::Rip => regs.rip,
            RegisterType::Eflags => regs.eflags,
            RegisterType::OrigRax => regs.orig_rax,
            RegisterType::Cs => regs.cs,
            RegisterType::Ds => regs.ds,
            RegisterType::Es => regs.es,
            RegisterType::Fs => regs.fs,
            RegisterType::Gs => regs.gs,
            RegisterType::Ss => regs.ss,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Register {
    pub reg_type: RegisterType,
    pub value: u64,
}
