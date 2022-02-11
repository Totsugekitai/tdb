#[allow(unused)]
use crate::{
    breakpoint::BreakpointManager,
    debug_info::{self, dump_debug_info, TdbDebugInfo},
    syscall::{get_regs, SyscallInfo, SyscallStack},
};
use libc::c_void;
use nix::{
    errno::Errno,
    libc::{PTRACE_O_TRACEEXEC, PTRACE_O_TRACESYSGOOD},
    sys::{
        ptrace,
        signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal},
        wait::{
            waitpid, WaitPidFlag,
            WaitStatus::{
                self, Continued, Exited, PtraceEvent, PtraceSyscall, Signaled, StillAlive, Stopped,
            },
        },
    },
    unistd::Pid,
};
use once_cell::sync::OnceCell;
use proc_maps::{get_process_maps, MapRange};
use std::{
    io::{self, BufRead, Write},
    path::Path,
    process::exit,
    sync::Mutex,
};

static CHILD_PID: OnceCell<Mutex<Pid>> = OnceCell::new();

fn init_child_pid(child: Pid) {
    CHILD_PID.set(Mutex::new(child)).unwrap();
}

extern "C" fn sigint_handler(_signum: libc::c_int) {
    let child_pid = CHILD_PID.get().unwrap().lock().unwrap();
    let _kr = signal::kill(*child_pid, Signal::SIGKILL);
    println!("kbd interrupt");
    exit(0);
}

pub fn debugger_main(child: Pid, filename: &str) {
    if let Err(e) = ptrace::attach(child) {
        panic!("ptrace::attach failed, errno: {e}");
    }

    // init
    init_child_pid(child);
    let mut syscall_stack = SyscallStack::new();
    let mut breakpoint_manager = BreakpointManager::new(child);
    let debug_info = TdbDebugInfo::init(filename);
    set_signal_handler();

    #[allow(unused_assignments)]
    let mut init_base = 0;
    let mut status;
    loop {
        let regs = ptrace::getregs(child);
        println!("{:x?}", &regs);

        let wait_options =
            WaitPidFlag::from_bits(WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits());
        status = waitpid(child, wait_options);

        if let Ok(m) = get_child_process_memory_info(child, filename) {
            init_base = m.start();
            break;
        } else {
            ptrace_syscall_catch_syscall(child, &mut syscall_stack);
        }
    }

    // 初回は特別扱いする
    {
        let regs = ptrace::getregs(child);
        println!("{:x?}", &regs);

        let command = match input_command(&debug_info) {
            Ok(command) => command,
            Err(e) => panic!("{}", e.to_string()),
        };

        match command {
            InputCommand::Breakpoint(offset) => {
                let base = init_base - 0x1000;
                println!("base: 0x{:x}", base);
                println!("offset: 0x{:x}", offset);
                let addr = (base + offset) as u64;
                // let byte = unsafe { set_breakpoint(child, addr) };
                let byte = breakpoint_manager.set(addr);
                println!(
                    "set breakpoint: 0x{:016x}, top: 0x{:x}",
                    addr,
                    byte.unwrap()
                );
            }
            InputCommand::StepInstruction => {}
            InputCommand::Continue => {
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
                    Continued(pid) => continued(pid),
                    Exited(pid, exit_code) => exited(pid, exit_code),
                    PtraceEvent(pid, signal, event) => ptrace_event(pid, signal, event),
                    PtraceSyscall(pid) => ptrace_syscall(pid, &mut syscall_stack),
                    Signaled(pid, signal, core_dump) => signaled(pid, signal, core_dump),
                    StillAlive => still_alive(),
                    Stopped(pid, signal) => stopped(pid, signal),
                }
            }
        }
    }

    loop {
        // dump_process_memory_info(child);
        let command = match input_command(&debug_info) {
            Ok(command) => command,
            Err(e) => {
                println!("{e}");
                continue;
            }
        };

        match command {
            InputCommand::Breakpoint(offset) => {
                let base = init_base - 0x1000;
                println!("base: 0x{:x}", base);
                println!("offset: 0x{:x}", offset);
                let addr = (base + offset) as u64;
                // let byte = unsafe { set_breakpoint(child, addr) };
                let byte = breakpoint_manager.set(addr);
                println!(
                    "set breakpoint: 0x{:016x}, top: 0x{:x}",
                    addr,
                    byte.unwrap()
                );
                continue;
            }
            InputCommand::StepInstruction => {}
            InputCommand::Continue => {
                let mut regs = ptrace::getregs(child).unwrap();
                println!("{:x?}", regs);
                let rip = regs.rip;
                let rip = rip - 1; // 0xccより1byteうしろにいるはず

                // dump_process_memory(child, rip, 0x10);
                // if let Some(val) = get_breakpoint_value(rip) {
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
            Continued(pid) => continued(pid),
            Exited(pid, exit_code) => exited(pid, exit_code),
            PtraceEvent(pid, signal, event) => ptrace_event(pid, signal, event),
            PtraceSyscall(pid) => ptrace_syscall(pid, &mut syscall_stack),
            Signaled(pid, signal, core_dump) => signaled(pid, signal, core_dump),
            StillAlive => still_alive(),
            Stopped(pid, signal) => stopped(pid, signal),
        }
    }
}

fn set_signal_handler() {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGINT);
    let handler = SigHandler::Handler(sigint_handler);
    let sigaction = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
    let _sigaction = unsafe { signal::sigaction(Signal::SIGINT, &sigaction) };
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
enum InputCommand {
    StepInstruction,
    Breakpoint(usize),
    Continue,
}

fn input_command(debug_info: &TdbDebugInfo) -> Result<InputCommand, io::Error> {
    let stdout = io::stdout();
    let mut out_handle = stdout.lock();
    let _ = out_handle.write(b"> ").unwrap();
    out_handle.flush().unwrap();

    let stdin = io::stdin();
    let mut in_handle = stdin.lock();

    let mut buf = String::new();
    in_handle.read_line(&mut buf).unwrap();
    let buf_vec: Vec<&str> = buf.split(' ').collect();
    let buf_vec: Vec<&str> = buf_vec.iter().map(|s| s.trim()).collect(); // read_line()で末尾に\nが付くため

    use self::InputCommand::*;
    use io::{Error, ErrorKind};
    match buf_vec[0] {
        "stepi" | "si" => Ok(StepInstruction),
        "break" | "b" => {
            if buf_vec.len() == 2 {
                let bp = buf_vec[1];
                let addr = if let Ok(u) = bp.parse::<usize>() {
                    u
                } else if let Some(address) = find_breakpoint_address(bp, debug_info) {
                    address
                } else {
                    return Err(Error::new(ErrorKind::NotFound, "breakpoint not found"));
                };
                Ok(Breakpoint(addr))
            } else {
                Err(Error::new(ErrorKind::InvalidInput, "invalid argument"))
            }
        }
        "continue" | "c" => Ok(Continue),
        _ => Err(Error::new(ErrorKind::NotFound, "command not found")),
    }
}

fn find_breakpoint_address(bp_str: &str, debug_info: &TdbDebugInfo) -> Option<usize> {
    debug_info::get_breakpoint_offset(bp_str, &debug_info.fn_info_vec)
}

fn get_child_process_memory_info(child: Pid, filename: &str) -> Result<MapRange, io::Error> {
    let maps = get_process_maps(child.as_raw()).unwrap();
    for map in maps {
        if map.is_exec() {
            let path_filename = map
                .filename()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap();

            let child_filename = Path::new(filename).file_name().unwrap().to_str().unwrap();

            if path_filename == child_filename {
                return Ok(map);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "child process not found",
    ))
}

#[allow(unused)]
fn dump_process_memory_map(child: Pid) {
    let maps = get_process_maps(child.as_raw()).unwrap();
    for map in maps {
        println!("{:x?}", map);
    }
}

#[allow(unused)]
fn dump_process_memory(pid: Pid, addr: usize, len: usize) {
    let num = if (len % 8) == 0 { len / 8 } else { len / 8 + 1 };
    for i in 0..num {
        let memdump = ptrace::read(pid, (addr + i * 8) as *mut c_void).unwrap();
        let memvec = memdump.to_le_bytes();
        for m in memvec {
            print!("{:02x} ", m);
        }
        println!();
    }
}
