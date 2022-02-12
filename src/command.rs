use crate::{
    debugger::DebuggerInfo,
    dump,
    syscall::{get_regs, SyscallInfo, SyscallStack},
};
use hex;
use nix::{
    libc::{PTRACE_O_TRACEEXEC, PTRACE_O_TRACESYSGOOD},
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::Pid,
};
use std::{
    io::{self, BufRead, Error, ErrorKind, Write},
    process::exit,
};

#[derive(Debug)]
pub enum Command {
    StepInstruction,
    Breakpoint(u64),
    Continue,
    DumpRegisters,
    ExamineMemory(u64, u64),
    ExamineMemoryMap,
    SymbolList,
}

impl Command {
    pub fn read(debugger_info: &DebuggerInfo) -> Result<Command, Box<dyn std::error::Error>> {
        let stdout = io::stdout();
        let mut out_handle = stdout.lock();
        out_handle.write_all(b"> ")?;
        out_handle.flush()?;

        let stdin = io::stdin();
        let mut in_handle = stdin.lock();

        let mut buf = String::new();
        in_handle.read_line(&mut buf)?;
        let buf_vec: Vec<&str> = buf.split(' ').collect();
        let buf_vec: Vec<&str> = buf_vec
            .iter()
            .map(|s| s.trim()) // read_line()で末尾に\nが付くため
            .filter(|s| !s.is_empty())
            .collect();

        use Command::*;
        match buf_vec[0] {
            "stepi" | "si" => Ok(StepInstruction),
            "break" | "b" => {
                if buf_vec.len() == 2 {
                    let bp = buf_vec[1];
                    let off = debugger_info.debug_info.get_breakpoint_offset(bp);
                    let off = match off {
                        Some(off) => off as u64,
                        None => bp.parse::<u64>()?,
                    };
                    Ok(Breakpoint(off))
                } else {
                    Err(Box::new(Error::new(
                        ErrorKind::InvalidInput,
                        "invalid argument",
                    )))
                }
            }
            "continue" | "c" => Ok(Continue),
            "regs" => Ok(DumpRegisters),
            "examine" | "x" => {
                let mut addr = 0;
                let prefix = &buf_vec[1][0..=1];
                if prefix == "0x" {
                    let hex_str = &buf_vec[1][2..];
                    let addr_decoded = hex::decode(hex_str)?;
                    for (i, d) in addr_decoded.iter().enumerate() {
                        addr += (*d as u64) << (addr_decoded.len() - 1 - i) * 8;
                    }
                } else {
                    addr = buf_vec[1].parse::<u64>()?;
                }

                let mut len = 0;
                let prefix = &buf_vec[2][0..=1];
                if prefix == "0x" {
                    let hex_str = &buf_vec[2][2..];
                    let len_decoded = hex::decode(hex_str)?;
                    for (i, d) in len_decoded.iter().enumerate() {
                        len += (*d as u64) << (len_decoded.len() - 1 - i) * 8;
                    }
                } else {
                    len = buf_vec[2].parse::<u64>()?;
                }

                Ok(ExamineMemory(addr, len))
            }
            "mmap" => Ok(ExamineMemoryMap),
            "ls" => Ok(SymbolList),
            _ => Err(Box::new(Error::new(
                ErrorKind::NotFound,
                "command not found",
            ))),
        }
    }

    pub fn exec(
        command: Command,
        debugger_info: &mut DebuggerInfo,
        status: WaitStatus,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use Command::*;
        match command {
            Breakpoint(offset) => {
                let base = debugger_info.base_addr;
                let addr = base + offset;
                let _byte = debugger_info.breakpoint_manager.set(addr)?;
                println!("set breakpoint at 0x{:016x}", addr);
                Ok(())
            }
            StepInstruction => Ok(()),
            Continue => {
                let ptrace_options =
                    ptrace::Options::from_bits(PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD).unwrap();
                ptrace::setoptions(debugger_info.child, ptrace_options)?;

                switch(status, debugger_info)
            }
            DumpRegisters => {
                let regs = get_regs(debugger_info.child);
                println!("{:x?}", regs);
                Ok(())
            }
            ExamineMemory(addr, len) => {
                dump::memory(debugger_info.child, addr, len);
                Ok(())
            }
            ExamineMemoryMap => {
                dump::memory_map(debugger_info.child);
                Ok(())
            }
            SymbolList => {
                dump::symbols(&debugger_info);
                Ok(())
            }
        }
    }
}

fn switch(
    status: WaitStatus,
    debugger_info: &mut DebuggerInfo,
) -> Result<(), Box<dyn std::error::Error>> {
    match status {
        WaitStatus::Continued(pid) => continued(pid),
        WaitStatus::Exited(pid, exit_code) => exited(pid, exit_code),
        WaitStatus::PtraceEvent(pid, signal, event) => ptrace_event(pid, signal, event),
        WaitStatus::PtraceSyscall(pid) => ptrace_syscall(pid, &mut debugger_info.syscall_stack),
        WaitStatus::Signaled(pid, signal, dump) => signaled(pid, signal, dump),
        WaitStatus::StillAlive => still_alive(),
        WaitStatus::Stopped(pid, signal) => stopped(pid, signal, debugger_info),
    }
    Ok(())
}

fn continued(pid: Pid) {
    println!("continued: PID: {pid}");
    if let Err(e) = ptrace::cont(pid, None) {
        panic!("ptrace::cont failed: errno = {:?}", e);
    }
}

fn exited(pid: Pid, exit_code: i32) -> ! {
    println!("exited: PID: {pid}, exit code: {exit_code}");
    exit(exit_code);
}

fn ptrace_event(pid: Pid, signal: Signal, event: i32) {
    println!("evented: PID: {pid}, Signal: {:?}, Event: {event}", signal);

    let regs = ptrace::getregs(pid).unwrap();
    println!("{:x?}", regs);

    if let Err(e) = ptrace::cont(pid, signal) {
        panic!("ptrace::cont failed: errno = {:?}", e);
    }
}

fn ptrace_syscall(pid: Pid, syscall_stack: &mut SyscallStack) {
    let syscall_info = SyscallInfo::from_regs(&get_regs(pid));

    if let Some(top) = syscall_stack.top() {
        // syscallの入口だった場合
        if top.number() != syscall_info.number() {
            println!(
                "syscall enter: PID: {pid}, {:03}: {}",
                syscall_info.number(),
                syscall_info.name()
            );
            syscall_stack.push(syscall_info);
        }
        // syscallの出口だった場合
        else if syscall_stack.pop().is_none() {
            panic!("syscall count failed");
        }
    } else {
        println!(
            "syscall enter: PID: {pid}, {:03}: {}",
            syscall_info.number(),
            syscall_info.name()
        );
        syscall_stack.push(syscall_info);
    }

    if let Err(e) = ptrace::cont(pid, None) {
        panic!("ptrace::syscall failed: errno = {:?}", e);
    }
}

fn signaled(pid: Pid, signal: Signal, _core_dump: bool) {
    println!("signaled: PID: {pid}, Signal: {:?}", signal);
    if let Err(e) = ptrace::cont(pid, signal) {
        println!("ptrace::cont failed: errno = {e}");
    }
}

fn still_alive() {
    println!("still alive");
}

fn stopped(pid: Pid, signal: Signal, debugger_info: &mut DebuggerInfo) {
    if signal == Signal::SIGTRAP {
        let regs = get_regs(pid);
        let addr = regs.rip - 1; // もしブレークポイントだったら0xCCより1byte次にいるはず
        if let Some(bp) = debugger_info.breakpoint_manager.get(addr) {
            bp.restore_memory(pid, regs).unwrap();
        } else {
            if let Err(e) = ptrace::cont(pid, None) {
                panic!("ptrace::cont failed: errno = {e}");
            }
            let wait_options = WaitPidFlag::from_bits(
                WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits(),
            );
            let status = waitpid(pid, wait_options).unwrap();
            switch(status, debugger_info).unwrap();
        }
        return;
    }

    if let Err(e) = ptrace::cont(pid, signal) {
        panic!("ptrace::cont failed: errno = {e}");
    }
}
