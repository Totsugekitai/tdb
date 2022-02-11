#[allow(unused)]
use crate::{
    breakpoint::BreakpointManager,
    command::Command,
    debug_info::{self, TdbDebugInfo},
    dump, mem,
    syscall::{get_regs, SyscallInfo, SyscallStack},
};
use nix::{
    sys::{
        ptrace,
        wait::{waitpid, WaitPidFlag},
    },
    unistd::Pid,
};

#[derive(Debug)]
pub struct DebuggerInfo {
    pub syscall_stack: SyscallStack,
    pub breakpoint_manager: BreakpointManager,
    pub debug_info: TdbDebugInfo,
    pub exec_base: Option<u64>,
    pub child: Pid,
}

pub fn debugger_main(child: Pid, filename: &str) {
    if let Err(e) = ptrace::attach(child) {
        panic!("ptrace::attach failed, errno: {e}");
    }

    // init
    crate::signal::init(child);
    let mut debugger_info = DebuggerInfo {
        syscall_stack: SyscallStack::new(),
        breakpoint_manager: BreakpointManager::new(child),
        debug_info: TdbDebugInfo::init(filename),
        exec_base: None,
        child,
    };

    let mut status;
    loop {
        let wait_options =
            WaitPidFlag::from_bits(WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits());
        status = waitpid(child, wait_options).unwrap();

        if let Ok(m) = mem::get_exec_segment_info(child, filename) {
            debugger_info.exec_base = Some(m.start() as u64);
            break;
        } else {
            catch_syscall(child, &mut debugger_info.syscall_stack);
        }
    }

    loop {
        let command = match Command::read(&debugger_info) {
            Ok(command) => command,
            Err(e) => {
                println!("{e}");
                continue;
            }
        };

        Command::exec(command, &mut debugger_info, status).unwrap();
    }
}

fn catch_syscall(pid: Pid, syscall_stack: &mut SyscallStack) {
    let syscall_info = SyscallInfo::from_regs(&get_regs(pid));

    if let Some(top) = syscall_stack.top() {
        // syscallの入口だった場合
        if top.number() != syscall_info.number() {
            syscall_stack.push(syscall_info);
        }
        // syscallの出口だった場合
        else if let None = syscall_stack.pop() {
            panic!("syscall count failed");
        }
    } else {
        syscall_stack.push(syscall_info);
    }

    if let Err(e) = ptrace::syscall(pid, None) {
        panic!("ptrace::syscall failed: errno = {:?}", e);
    }
}
