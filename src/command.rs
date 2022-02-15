use crate::{
    debugger::{DebuggerInfo, WatchPoint},
    dump, mem, register,
    syscall::{get_regs, SyscallInfo, SyscallStack},
    util::parse_demical_or_hex,
};
use nix::{
    libc::c_void,
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
    Memory(mem::Memory),
    Register(register::Register),
}

// #[derive(Debug, Clone)]
// enum ListCommand {
//     Function,
//     Variable,
// }

impl Command {
    pub fn read(debugger_info: &mut DebuggerInfo) -> Result<Command, Box<dyn std::error::Error>> {
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
            "stepi" | "si" => {
                debugger_info.cont_flag = false;
                Ok(StepInstruction)
            }
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
                    let value =
                        ptrace::read(debugger_info.debug_info.target_pid, addr as *mut c_void)
                            .unwrap() as u64;
                    Ok(Watch(WatchCommand::Memory(mem::Memory { addr, value })))
                } else if let Ok(reg_type) = register::RegisterType::parse(buf_vec[1]) {
                    let value = reg_type.get_current_value(debugger_info.debug_info.target_pid);
                    Ok(Watch(WatchCommand::Register(register::Register {
                        reg_type,
                        value,
                    })))
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

    /// command execution
    /// returns (wait status after command execution, additional command)
    pub fn exec(
        command: Command,
        debugger_info: &mut DebuggerInfo,
        status: WaitStatus,
    ) -> Result<(WaitStatus, Option<Command>), Box<dyn std::error::Error>> {
        use Command::*;
        let status_and_additional_command = match command {
            Empty(prev_command) => {
                if let Some(command) = *prev_command {
                    Self::exec(command, debugger_info, status).unwrap()
                } else {
                    println!("command not found");
                    (status, None)
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
                (status, None)
            }
            StepInstruction => {
                debugger_info.prev_command = Some(command);
                let status = single_step(debugger_info).unwrap();
                let regs = get_regs(debugger_info.debug_info.target_pid);
                let rip = regs.rip;
                if !debugger_info.cont_flag {
                    println!("rip = 0x{:016x}", rip);
                }
                status
            }
            Continue => {
                debugger_info.cont_flag = true;
                debugger_info.prev_command = Some(command);
                continue_run(status, debugger_info).unwrap()
            }
            DumpRegisters => {
                dump::register(debugger_info.debug_info.target_pid);
                debugger_info.prev_command = Some(command);
                (status, None)
            }
            ExamineMemory(addr, len) => {
                dump::memory(&debugger_info.debug_info, addr, len);
                debugger_info.prev_command = Some(command);
                (status, None)
            }
            ExamineMemoryMap => {
                dump::memory_map(debugger_info.debug_info.target_pid);
                debugger_info.prev_command = Some(command);
                (status, None)
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
                (status, None)
            }
            Backtrace => {
                dump::backtrace(&debugger_info.debug_info);
                debugger_info.prev_command = Some(command);
                (status, None)
            }
            Watch(watch_command) => match watch_command {
                WatchCommand::Memory(mem) => {
                    debugger_info.set_watchpoint(WatchPoint::Memory(mem));
                    (status, None)
                }
                WatchCommand::Register(reg) => {
                    debugger_info.set_watchpoint(WatchPoint::Register(reg));
                    (status, None)
                }
            },
        };
        Ok(status_and_additional_command)
    }
}

fn switch_by_wait_status(
    status: WaitStatus,
    debugger_info: &mut DebuggerInfo,
) -> Result<(WaitStatus, Option<Command>), Box<dyn std::error::Error>> {
    let status = match status {
        WaitStatus::Continued(pid) => (continued(pid), None),
        WaitStatus::Exited(pid, exit_code) => exited(pid, exit_code),
        WaitStatus::PtraceEvent(pid, signal, event) => (ptrace_event(pid, signal, event), None),
        WaitStatus::PtraceSyscall(pid) => {
            (ptrace_syscall(pid, &mut debugger_info.syscall_stack), None)
        }
        WaitStatus::Signaled(pid, signal, dump) => (signaled(pid, signal, dump), None),
        WaitStatus::StillAlive => (still_alive(debugger_info.debug_info.target_pid), None),
        WaitStatus::Stopped(pid, signal) => stopped(pid, signal, debugger_info),
    };
    Ok(status)
}

fn continued(pid: Pid) -> WaitStatus {
    println!("continued: PID: {pid}");
    if let Err(e) = ptrace::cont(pid, None) {
        panic!("ptrace::cont failed: errno = {:?}", e);
    }

    waitpid(pid, None).unwrap()
}

fn exited(pid: Pid, exit_code: i32) -> ! {
    println!("exited: PID: {pid}, exit code: {exit_code}");
    exit(exit_code);
}

fn ptrace_event(pid: Pid, signal: Signal, event: i32) -> WaitStatus {
    println!("evented: PID: {pid}, Signal: {:?}, Event: {event}", signal);

    let regs = ptrace::getregs(pid).unwrap();
    println!("{:x?}", regs);

    if let Err(e) = ptrace::cont(pid, signal) {
        panic!("ptrace::cont failed: errno = {:?}", e);
    }

    waitpid(pid, None).unwrap()
}

fn ptrace_syscall(pid: Pid, syscall_stack: &mut SyscallStack) -> WaitStatus {
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

    waitpid(pid, None).unwrap()
}

fn signaled(pid: Pid, signal: Signal, _core_dump: bool) -> WaitStatus {
    println!("signaled: PID: {pid}, Signal: {:?}", signal);
    if let Err(e) = ptrace::cont(pid, signal) {
        println!("ptrace::cont failed: errno = {e}");
    }
    waitpid(pid, None).unwrap()
}

fn still_alive(pid: Pid) -> WaitStatus {
    println!("still alive");
    if let Err(e) = ptrace::cont(pid, None) {
        println!("ptrace::cont failed: errno = {e}");
    }
    waitpid(pid, None).unwrap()
}

fn stopped(
    pid: Pid,
    signal: Signal,
    debugger_info: &mut DebuggerInfo,
) -> (WaitStatus, Option<Command>) {
    if signal == Signal::SIGTRAP {
        let regs = get_regs(pid);
        // もしブレークポイントだったら0xCCより1byte次にいるはず
        let addr = regs.rip - 1;
        // 上のアドレスがブレークポイントだったとき
        if let Some(bp) = debugger_info.breakpoint_manager.get(addr) {
            bp.restore_memory(pid, regs).unwrap();
            return (
                WaitStatus::Stopped(debugger_info.debug_info.target_pid, Signal::SIGTRAP),
                None,
            );
        }
        // ブレークポイントではなかったとき
        else {
            // ウォッチポイントが仕掛けられていないときはcontしてもどる
            if debugger_info.watch_list.is_empty() {
                if let Err(e) = ptrace::cont(pid, None) {
                    panic!("ptrace::cont failed: errno = {e}");
                }
                let status = waitpid(debugger_info.debug_info.target_pid, None).unwrap();
                if status
                    == WaitStatus::Stopped(debugger_info.debug_info.target_pid, Signal::SIGTRAP)
                {
                    return (status, Some(Command::Continue));
                } else {
                    return (status, None);
                }
            }
            // ウォッチポイントが仕掛けられているときはstepしてさらにStep Instruction Commandを発行
            else {
                ptrace::step(debugger_info.debug_info.target_pid, None).unwrap();
                let status = waitpid(debugger_info.debug_info.target_pid, None).unwrap();
                debugger_info.cont_flag = true;
                return (status, Some(Command::StepInstruction));
            }
        }
    }

    if let Err(e) = ptrace::cont(pid, signal) {
        panic!("ptrace::cont failed: errno = {e}");
    }
    (
        waitpid(debugger_info.debug_info.target_pid, None).unwrap(),
        None,
    )
}

fn single_step(
    debugger_info: &mut DebuggerInfo,
) -> Result<(WaitStatus, Option<Command>), Box<dyn std::error::Error>> {
    ptrace::step(debugger_info.debug_info.target_pid, None)?;
    let wait_options =
        WaitPidFlag::from_bits(WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits());

    let wait_status = waitpid(debugger_info.debug_info.target_pid, wait_options).unwrap();
    // println!("{:?}", wait_status);

    if !debugger_info.cont_flag {
        return Ok((
            WaitStatus::Stopped(debugger_info.debug_info.target_pid, Signal::SIGTRAP),
            None,
        ));
    }

    if let WaitStatus::Exited(_pid, code) = wait_status {
        exit(code);
    }
    let regs = get_regs(debugger_info.debug_info.target_pid);
    // もしブレークポイントだったら0xCCより1byte次にいるはず
    let addr = regs.rip - 1;
    // 上のアドレスがブレークポイントだったとき
    if let Some(bp) = debugger_info.breakpoint_manager.get(addr) {
        bp.restore_memory(debugger_info.debug_info.target_pid, regs)
            .unwrap();
        debugger_info.cont_flag = false;
        Ok((
            WaitStatus::Stopped(debugger_info.debug_info.target_pid, Signal::SIGTRAP),
            None,
        ))
    }
    // ブレークポイントではなかったとき
    else {
        // ウォッチポイントが仕掛けられていないときはcontしてもどる
        if debugger_info.watch_list.is_empty() {
            debugger_info.cont_flag = false;
            if let Err(e) = ptrace::cont(debugger_info.debug_info.target_pid, None) {
                panic!("ptrace::cont failed: errno = {e}");
            }
            let status = waitpid(debugger_info.debug_info.target_pid, None).unwrap();
            if status == WaitStatus::Stopped(debugger_info.debug_info.target_pid, Signal::SIGTRAP) {
                Ok((status, Some(Command::Continue)))
            } else {
                Ok((status, None))
            }
        }
        // ウォッチポイントが仕掛けられているときはstepしてさらにStep Instruction Commandを発行
        else {
            debugger_info.cont_flag = true;
            ptrace::step(debugger_info.debug_info.target_pid, None).unwrap();
            let status = waitpid(debugger_info.debug_info.target_pid, None).unwrap();
            Ok((status, Some(Command::StepInstruction)))
        }
    }
}

fn continue_run(
    status: WaitStatus,
    debugger_info: &mut DebuggerInfo,
) -> Result<(WaitStatus, Option<Command>), Box<dyn std::error::Error>> {
    debugger_info.cont_flag = true;
    let wait_status = switch_by_wait_status(status, debugger_info).unwrap();
    Ok(wait_status)
}
