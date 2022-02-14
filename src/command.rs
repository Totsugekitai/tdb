use crate::{
    debugger::{DebuggerInfo, Watchable},
    dump, mem, register,
    syscall::{get_regs, SyscallInfo, SyscallStack},
    util::parse_demical_or_hex,
};
use nix::{
    libc::{c_void, PTRACE_O_TRACEEXEC, PTRACE_O_TRACESYSGOOD},
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

#[derive(Debug, Clone)]
pub enum Command {
    Empty(Box<Option<Command>>),
    StepInstruction,
    Breakpoint(u64),
    Continue,
    DumpRegisters,
    ExamineMemory(u64, u64),
    ExamineMemoryMap,
    List(Vec<String>),
    Backtrace,
    Watch(WatchCommand),
}

#[derive(Debug, Clone)]
pub enum WatchCommand {
    Memory(mem::Address),
    Register(register::Register),
}

// #[derive(Debug, Clone)]
// enum ListCommand {
//     Function,
//     Variable,
// }

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

        if buf_vec.is_empty() {
            let prev = debugger_info.prev_command.clone();
            return Ok(Empty(Box::new(prev)));
        }

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
                let addr = parse_demical_or_hex(buf_vec[1])?;
                let len = parse_demical_or_hex(buf_vec[2])?;
                Ok(ExamineMemory(addr, len))
            }
            "mmap" => Ok(ExamineMemoryMap),
            "ls" => {
                let sub_commands = buf_vec[1..]
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<String>>();
                Ok(List(sub_commands))
            }
            "backtrace" | "bt" => Ok(Backtrace),
            "watch" | "w" => {
                if let Ok(addr) = parse_demical_or_hex(buf_vec[1]) {
                    Ok(Watch(WatchCommand::Memory(mem::Address(addr))))
                } else if let Ok(reg) = crate::register::Register::parse(buf_vec[1]) {
                    Ok(Watch(WatchCommand::Register(reg)))
                } else {
                    Err(Box::new(Error::new(
                        ErrorKind::InvalidInput,
                        "invalid argument",
                    )))
                }
            }
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
            Empty(prev_command) => {
                if let Some(command) = *prev_command {
                    return Self::exec(command, debugger_info, status);
                } else {
                    println!("command not found");
                }
            }
            Breakpoint(bin_offset) => {
                // とりあえずコードセグメントが1つだけのバイナリに対応
                let exec_map = debugger_info.debug_info.exec_maps().unwrap()[0];
                // mapが実際にある仮想アドレス
                let start = exec_map.start() as u64;
                // バイナリファイルのどこからがこの領域にマップされているかを指し示す値
                // addrの計算に必要
                let offset = exec_map.offset as u64;
                // ブレークポイントの実際のアドレス
                let addr = start + (bin_offset - offset);
                let _byte = debugger_info.breakpoint_manager.set(addr)?;
                println!("set breakpoint at 0x{:016x}", addr);
                debugger_info.prev_command = Some(command);
            }
            StepInstruction => {
                debugger_info.prev_command = Some(command);
                return single_step(debugger_info);
            }
            Continue => {
                let ptrace_options =
                    ptrace::Options::from_bits(PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD).unwrap();
                ptrace::setoptions(debugger_info.debug_info.target_pid, ptrace_options)?;
                debugger_info.prev_command = Some(command);

                return switch(status, debugger_info);
            }
            DumpRegisters => {
                dump::register(debugger_info.debug_info.target_pid);
                debugger_info.prev_command = Some(command);
            }
            ExamineMemory(addr, len) => {
                dump::memory(&debugger_info.debug_info, addr, len);
                debugger_info.prev_command = Some(command);
            }
            ExamineMemoryMap => {
                dump::memory_map(debugger_info.debug_info.target_pid);
                debugger_info.prev_command = Some(command);
            }
            List(sub_commands) => {
                if sub_commands.is_empty() {
                    dump::all_symbols(debugger_info);
                } else {
                    let sub_command = &sub_commands[0];
                    match sub_command.as_str() {
                        "f" => dump::functions(debugger_info),
                        "v" => dump::variables(debugger_info),
                        "misc" => dump::misc_symbols(&debugger_info.debug_info),
                        "w" => dump::watchpoints(debugger_info),
                        _ => println!("invalid ls sub command"),
                    }
                }
                let command = Command::List(sub_commands);
                debugger_info.prev_command = Some(command);
            }
            Backtrace => {
                dump::backtrace(&debugger_info.debug_info);
                debugger_info.prev_command = Some(command);
            }
            Watch(watch_command) => match watch_command {
                WatchCommand::Memory(addr) => {
                    let init_value =
                        ptrace::read(debugger_info.debug_info.target_pid, addr.0 as *mut c_void)
                            .unwrap() as u64;
                    debugger_info.set_watchpoint(Watchable::Address(addr), init_value);
                }
                WatchCommand::Register(reg) => {
                    let init_value = reg.get_value(&debugger_info.debug_info);
                    debugger_info.set_watchpoint(Watchable::Register(reg), init_value);
                }
            },
        }
        Ok(())
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
        if debugger_info.step_flag {
            debugger_info.step_flag = false;
            return;
        }
        let regs = get_regs(pid);
        // もしブレークポイントだったら0xCCより1byte次にいるはず
        let addr = regs.rip - 1;
        // 上のアドレスがブレークポイントだったとき
        if let Some(bp) = debugger_info.breakpoint_manager.get(addr) {
            bp.restore_memory(pid, regs).unwrap();
        }
        // ブレークポイントではなかったとき
        else {
            // ウォッチポイントが仕掛けられていないときは普通にcont
            if debugger_info.watch_list.is_empty() {
                if let Err(e) = ptrace::cont(pid, None) {
                    panic!("ptrace::cont failed: errno = {e}");
                }
                let wait_options = WaitPidFlag::from_bits(
                    WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits(),
                );
                let status = waitpid(pid, wait_options).unwrap();
                switch(status, debugger_info).unwrap();
            }
            // ウォッチポイントが仕掛けられているときはstep実行
            else {
                if let Err(e) = ptrace::step(pid, None) {
                    panic!("ptrace::cont failed: errno = {e}");
                }
                let wait_options = WaitPidFlag::from_bits(
                    WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits(),
                );
                let status = waitpid(pid, wait_options).unwrap();

                // ウォッチポイントを検査する
                for (watchpoint, value) in debugger_info.watch_list.iter_mut() {
                    match watchpoint {
                        Watchable::Address(addr) => {
                            let current_value = ptrace::read(
                                debugger_info.debug_info.target_pid,
                                addr.0 as *mut c_void,
                            )
                            .unwrap() as u64;
                            if current_value != *value {
                                println!(
                                    "detect value change! 0x{:016x}: 0x{:x} -> 0x{:x}",
                                    addr.0, value, current_value
                                );
                                *value = current_value;
                                return;
                            }
                        }
                        Watchable::Register(reg) => {
                            let regs = get_regs(debugger_info.debug_info.target_pid);
                            use register::Register;
                            let current_value = match reg {
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
                            };
                            if current_value != *value {
                                println!(
                                    "detect value change! {:?}: 0x{:x} -> 0x{:x}",
                                    reg, value, current_value
                                );
                                *value = current_value;
                                return;
                            }
                        }
                    }
                }

                switch(status, debugger_info).unwrap();
            }
        }
        return;
    }

    if let Err(e) = ptrace::cont(pid, signal) {
        panic!("ptrace::cont failed: errno = {e}");
    }
}

fn single_step(debugger_info: &mut DebuggerInfo) -> Result<(), Box<dyn std::error::Error>> {
    debugger_info.step_flag = true;
    ptrace::step(debugger_info.debug_info.target_pid, None)?;
    let wait_options =
        WaitPidFlag::from_bits(WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits());
    let status = waitpid(debugger_info.debug_info.target_pid, wait_options).unwrap();

    let regs = get_regs(debugger_info.debug_info.target_pid);
    if !debugger_info.watch_list.is_empty() {}
    let rip = regs.rip;
    println!("rip = 0x{:016x}", rip);

    switch(status, debugger_info)
}
