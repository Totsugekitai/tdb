#[allow(unused)]
use crate::{
    breakpoint::BreakpointManager,
    debug_info::{self, TdbDebugInfo},
    dump, mem,
    syscall::{get_regs, SyscallInfo, SyscallStack},
};
use libc::c_void;
use nix::{
    errno::Errno,
    libc::{PTRACE_O_TRACEEXEC, PTRACE_O_TRACESYSGOOD},
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::Pid,
};
use std::{
    io::{self, BufRead, Write},
    process::exit,
};

pub fn debugger_main(child: Pid, filename: &str) {
    if let Err(e) = ptrace::attach(child) {
        panic!("ptrace::attach failed, errno: {e}");
    }

    // init
    crate::signal::init(child);
    let mut syscall_stack = SyscallStack::new();
    let mut breakpoint_manager = BreakpointManager::new(child);
    let debug_info = TdbDebugInfo::init(filename);

    let init_base;
    let mut status;
    loop {
        dump::register(child);

        let wait_options =
            WaitPidFlag::from_bits(WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits());
        status = waitpid(child, wait_options);

        if let Ok(m) = mem::get_exec_segment_info(child, filename) {
            init_base = m.start();
            break;
        } else {
            ptrace_syscall_catch_syscall(child, &mut syscall_stack);
        }
    }

    // 初回は特別扱いする
    {
        dump::register(child);

        let command = match Command::read(&debug_info) {
            Ok(command) => command,
            Err(e) => panic!("{}", e.to_string()),
        };

        match command {
            Command::Breakpoint(offset) => {
                let base = init_base - 0x1000;
                println!("base: 0x{:x}", base);
                println!("offset: 0x{:x}", offset);
                let addr = (base + offset) as u64;
                let byte = breakpoint_manager.set(addr);
                println!(
                    "set breakpoint: 0x{:016x}, top: 0x{:x}",
                    addr,
                    byte.unwrap()
                );
            }
            Command::StepInstruction => {}
            Command::Continue => {
                let status = match status {
                    Ok(status) => {
                        let ptrace_options =
                            ptrace::Options::from_bits(PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD)
                                .unwrap();
                        let _ = ptrace::setoptions(child, ptrace_options);
                        status
                    }
                    Err(e) => {
                        if e == Errno::ECHILD {
                            println!("process already exited");
                            WaitStatus::Exited(child, 0)
                        } else {
                            WaitStatus::Exited(child, e as i32)
                        }
                    }
                };

                match status {
                    WaitStatus::Continued(pid) => continued(pid),
                    WaitStatus::Exited(pid, exit_code) => exited(pid, exit_code),
                    WaitStatus::PtraceEvent(pid, signal, event) => ptrace_event(pid, signal, event),
                    WaitStatus::PtraceSyscall(pid) => ptrace_syscall(pid, &mut syscall_stack),
                    WaitStatus::Signaled(pid, signal, dump) => signaled(pid, signal, dump),
                    WaitStatus::StillAlive => still_alive(),
                    WaitStatus::Stopped(pid, signal) => stopped(pid, signal),
                }
            }
        }
    }

    loop {
        let command = match Command::read(&debug_info) {
            Ok(command) => command,
            Err(e) => {
                println!("{e}");
                continue;
            }
        };

        match command {
            Command::Breakpoint(offset) => {
                let base = init_base - 0x1000;
                println!("base: 0x{:x}", base);
                println!("offset: 0x{:x}", offset);
                let addr = (base + offset) as u64;
                let byte = breakpoint_manager.set(addr);
                println!(
                    "set breakpoint: 0x{:016x}, top: 0x{:x}",
                    addr,
                    byte.unwrap()
                );
                continue;
            }
            Command::StepInstruction => {}
            Command::Continue => {
                let mut regs = ptrace::getregs(child).unwrap();
                println!("{:x?}", regs);
                let rip = regs.rip;
                let rip = rip - 1; // 0xccより1byteうしろにいるはず

                if let Some(val) = breakpoint_manager.get(rip) {
                    println!("breakpoint!");
                    let data = ptrace::read(child, rip as *const c_void as *mut c_void).unwrap();
                    let mut data_vec = data.to_le_bytes();
                    if data_vec[0] == 0xcc {
                        data_vec[0] = val;
                    } else {
                        panic!(
                            "bad breakpoint! addr: 0x{:x}, value: 0x{:x}",
                            rip, data_vec[0]
                        );
                    }
                    let mut data_long = 0;
                    for i in 0..(data_vec.len()) {
                        data_long += (data_vec[i as usize] as u64) << (i * 8);
                    }
                    unsafe {
                        ptrace::write(
                            child,
                            rip as *const c_void as *mut c_void,
                            data_long as *mut c_void,
                        )
                        .unwrap();
                    }
                    regs.rip = rip;
                    ptrace::setregs(child, regs).unwrap();
                }
            }
        }

        let status = match status {
            Ok(status) => {
                let ptrace_options =
                    ptrace::Options::from_bits(PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD).unwrap();
                let _ = ptrace::setoptions(child, ptrace_options);
                status
            }
            Err(e) => {
                if e == Errno::ECHILD {
                    println!("process already exited");
                    WaitStatus::Exited(child, 0)
                } else {
                    WaitStatus::Exited(child, e as i32)
                }
            }
        };

        match status {
            WaitStatus::Continued(pid) => continued(pid),
            WaitStatus::Exited(pid, exit_code) => exited(pid, exit_code),
            WaitStatus::PtraceEvent(pid, signal, event) => ptrace_event(pid, signal, event),
            WaitStatus::PtraceSyscall(pid) => ptrace_syscall(pid, &mut syscall_stack),
            WaitStatus::Signaled(pid, signal, dump) => signaled(pid, signal, dump),
            WaitStatus::StillAlive => still_alive(),
            WaitStatus::Stopped(pid, signal) => stopped(pid, signal),
        }
    }
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
    // let syscall_info = get_syscall_info(&get_regs(pid));
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
        else if let Some(_s) = syscall_stack.pop() {
            // println!("syscall exit : {}", s.name);
        } else {
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

fn ptrace_syscall_catch_syscall(pid: Pid, syscall_stack: &mut SyscallStack) {
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
        else if let Some(s) = syscall_stack.pop() {
            println!("syscall exit : {}", s.name());
        } else {
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

    if let Err(e) = ptrace::syscall(pid, None) {
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

fn stopped(pid: Pid, signal: Signal) {
    println!("stopped: PID: {pid}, Signal: {:?}", signal);

    if signal == Signal::SIGTRAP {
        let signal = None;
        if let Err(e) = ptrace::cont(pid, signal) {
            panic!("ptrace::cont failed: errno = {e}");
        }
        return;
    }

    if let Err(e) = ptrace::cont(pid, signal) {
        panic!("ptrace::cont failed: errno = {e}");
    }
}

#[derive(Debug)]
enum Command {
    StepInstruction,
    Breakpoint(usize),
    Continue,
}

impl Command {
    fn read(debug_info: &TdbDebugInfo) -> Result<Command, Box<dyn std::error::Error>> {
        let stdout = io::stdout();
        let mut out_handle = stdout.lock();
        out_handle.write_all(b"> ")?;
        out_handle.flush()?;

        let stdin = io::stdin();
        let mut in_handle = stdin.lock();

        let mut buf = String::new();
        in_handle.read_line(&mut buf)?;
        let buf_vec: Vec<&str> = buf.split(' ').collect();
        let buf_vec: Vec<&str> = buf_vec.iter().map(|s| s.trim()).collect(); // read_line()で末尾に\nが付くため

        use self::Command::*;
        use io::{Error, ErrorKind};
        match buf_vec[0] {
            "stepi" | "si" => Ok(StepInstruction),
            "break" | "b" => {
                if buf_vec.len() == 2 {
                    let bp = buf_vec[1];
                    let off = debug_info.get_breakpoint_offset(bp);
                    let off = match off {
                        Some(off) => off,
                        None => bp.parse::<usize>()?,
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
            _ => Err(Box::new(Error::new(
                ErrorKind::NotFound,
                "command not found",
            ))),
        }
    }
}
