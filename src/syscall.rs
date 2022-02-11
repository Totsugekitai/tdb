#![allow(unused)]
use libc::user_regs_struct;
use nix::{sys::ptrace, unistd::Pid};
use once_cell::sync::OnceCell;
use std::{collections::LinkedList, fmt, sync::Mutex};
use syscalls::Sysno;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SyscallNumber(u64);

impl SyscallNumber {
    fn new(n: u64) -> Self {
        Self(n)
    }

    fn from_regs(regs: &user_regs_struct) -> Self {
        Self(regs.orig_rax)
    }
}

impl fmt::Display for SyscallNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct SyscallInfo {
    number: SyscallNumber,
    name: String,
}

impl SyscallInfo {
    pub fn from_regs(regs: &user_regs_struct) -> Self {
        let orig_rax = regs.orig_rax;
        let sysno = Sysno::new(orig_rax as usize).unwrap();
        let name = String::from(sysno.name());
        let number = SyscallNumber::new(orig_rax);
        Self { number, name }
    }

    pub fn number(&self) -> SyscallNumber {
        self.number
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug)]
pub struct SyscallStack(LinkedList<SyscallInfo>);

impl SyscallStack {
    pub fn new() -> Self {
        Self(LinkedList::new())
    }

    pub fn push(&mut self, info: SyscallInfo) {
        self.0.push_front(info);
    }

    pub fn pop(&mut self) -> Option<SyscallInfo> {
        self.0.pop_front()
    }

    pub fn top(&self) -> Option<&SyscallInfo> {
        self.0.front()
    }

    pub fn is_exit(&self, n: SyscallNumber) -> bool {
        let front = self.top();
        match self.top() {
            Some(t) => n == t.number(),
            None => false,
        }
    }
}

pub fn get_regs(pid: Pid) -> user_regs_struct {
    ptrace::getregs(pid).unwrap()
}
