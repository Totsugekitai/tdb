#![allow(unused)]

use libc::user_regs_struct;
use nix::{sys::ptrace, unistd::Pid};
use once_cell::sync::OnceCell;
use std::{collections::LinkedList, sync::Mutex};
use syscalls::Sysno;

type SyscallNumber = u64;

#[derive(Debug, Clone)]
pub struct SyscallInfo {
    pub number: SyscallNumber,
    pub name: String,
}

#[derive(Debug)]
pub struct SyscallStack(LinkedList<SyscallInfo>);

impl SyscallStack {
    fn push(&mut self, info: SyscallInfo) {
        self.0.push_front(info);
    }

    fn pop(&mut self) -> Option<SyscallInfo> {
        self.0.pop_front()
    }

    fn get_top_syscall_number(&self) -> Option<SyscallNumber> {
        let info = self.0.front();
        info.map(|info| info.number)
    }
}

static SYSCALL_STACK: OnceCell<Mutex<SyscallStack>> = OnceCell::new();

pub fn init_syscall_stack() {
    SYSCALL_STACK.set(Mutex::new(SyscallStack(LinkedList::new())));
}

pub fn get_syscall_info(regs: &user_regs_struct) -> SyscallInfo {
    let number = get_syscall_number(regs);
    let sysno = Sysno::new(number as usize).unwrap();
    let name = String::from(sysno.name());
    SyscallInfo { number, name }
}

pub fn get_regs(pid: Pid) -> user_regs_struct {
    ptrace::getregs(pid).unwrap()
}

fn get_syscall_number(regs: &user_regs_struct) -> SyscallNumber {
    regs.orig_rax
}

pub fn push_syscall_stack(info: SyscallInfo) {
    let mut syscall_stack = SYSCALL_STACK.get().unwrap().lock().unwrap();
    syscall_stack.push(info);
}

pub fn pop_syscall_stack() -> Option<SyscallInfo> {
    let mut syscall_stack = SYSCALL_STACK.get().unwrap().lock().unwrap();
    syscall_stack.pop()
}

pub fn top_syscall_number_in_syscall_stack() -> Option<SyscallNumber> {
    let mut syscall_stack = SYSCALL_STACK.get().unwrap().lock().unwrap();
    syscall_stack.get_top_syscall_number()
}

pub fn is_exit(syscall_number: SyscallNumber) -> bool {
    let syscall_stack = SYSCALL_STACK.get().unwrap().lock().unwrap();
    let front = syscall_stack.get_top_syscall_number();
    if let Some(n) = front {
        n == syscall_number
    } else {
        false
    }
}
