#[allow(unused)]
use crate::{
    debug_info::{self, dump_debug_info, TdbDebugInfo},
    syscall::{
        get_regs, get_syscall_info, init_syscall_stack, pop_syscall_stack, push_syscall_stack,
        top_syscall_number_in_syscall_stack,
    },
    DEBUGGER_NAME,
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
    collections::BTreeMap,
    io::{self, BufRead, Write},
    path::Path,
    process::exit,
    sync::Mutex,
};

static CHILD_PID: OnceCell<Mutex<Pid>> = OnceCell::new();

fn init_child_pid(child: Pid) {
    let _ = CHILD_PID.set(Mutex::new(child));
}

pub fn debugger_main(child: Pid, filename: &str) {
    if let Err(e) = ptrace::attach(child) {
        panic!("ptrace::attach failed, errno: {e}");
    }

    // init
    init_syscall_stack();
    init_breakpoints_map();
    init_child_pid(child);
    let debug_info = TdbDebugInfo::init(filename);
    set_signal_handler();

    // dump_debug_info(filename);

    #[allow(unused_assignments)]
    let mut init_base = 0;
    let mut status;
    // let mut len = 0;
    loop {
        // dump_process_memory_info(child);
        let regs = ptrace::getregs(child);
        println!("{:x?}", &regs);

        let wait_options =
            WaitPidFlag::from_bits(WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits());
        status = waitpid(child, wait_options);

        if let Ok(m) = get_child_process_memory_info(child, filename) {
            init_base = m.start();
            // len = m.size();
            break;
        } else {
            ptrace_syscall_catch_syscall(child);
        }
    }

    // 初回は特別扱いする
    {
        let regs = ptrace::getregs(child);
        println!("{:x?}", &regs);
        // dump_process_memory_info(child);

        let command = match input_command(&debug_info) {
            Ok(command) => command,
            Err(e) => panic!("{}", e.to_string()),
        };

        match command {
            InputCommand::Breakpoint(offset) => {
                let base = init_base - 0x1000;
                println!("base: 0x{:x}", base);
                println!("offset: 0x{:x}", offset);
                let addr = base + offset;
                let byte = unsafe { set_breakpoint(child, addr) };
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
                    PtraceSyscall(pid) => ptrace_syscall(pid),
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
                println!("{}", e.to_string());
                continue;
            }
        };

        match command {
            InputCommand::Breakpoint(offset) => {
                let base = init_base - 0x1000;
                println!("base: 0x{:x}", base);
                println!("offset: 0x{:x}", offset);
                let addr = base + offset;
                let byte = unsafe { set_breakpoint(child, addr) };
                println!(
                    "set breakpoint: 0x{:016x}, top: 0x{:x}",
                    addr,
                    byte.unwrap()
                );
                continue;
            }
            InputCommand::StepInstruction => {}
            InputCommand::Continue => {}
        }

        // let wait_options =
        //     WaitPidFlag::from_bits(WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits());
        // let status = waitpid(child, wait_options);

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
            PtraceSyscall(pid) => ptrace_syscall(pid),
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

extern "C" fn sigint_handler(_signum: libc::c_int) {
    let child_pid = CHILD_PID.get().unwrap().lock().unwrap();
    let _kr = signal::kill(*child_pid, Signal::SIGKILL);
    println!("kbd interrupt");
    exit(0);
}

fn continued(pid: Pid) {
    println!("continued: PID: {pid}");
    if let Err(e) = ptrace::cont(pid, None) {
        panic!("ptrace::cont failed: errno = {:?}", e);
    }
}

fn exited(pid: Pid, exit_code: i32) {
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

fn ptrace_syscall(pid: Pid) {
    let syscall_info = get_syscall_info(&get_regs(pid));

    if let Some(top_syscall_number) = top_syscall_number_in_syscall_stack() {
        // syscallの入口だった場合
        if top_syscall_number != syscall_info.number {
            println!(
                "syscall enter: PID: {pid}, {:03}: {}",
                syscall_info.number, syscall_info.name
            );
            push_syscall_stack(syscall_info);
        }
        // syscallの出口だった場合
        else {
            if let Some(s) = pop_syscall_stack() {
                println!("syscall exit : {}", s.name);
            } else {
                panic!("syscall count failed");
            }
        }
    } else {
        println!(
            "syscall enter: PID: {pid}, {:03}: {}",
            syscall_info.number, syscall_info.name
        );
        push_syscall_stack(syscall_info);
    }

    if let Err(e) = ptrace::cont(pid, None) {
        panic!("ptrace::syscall failed: errno = {:?}", e);
    }
}

fn ptrace_syscall_catch_syscall(pid: Pid) {
    let syscall_info = get_syscall_info(&get_regs(pid));

    if let Some(top_syscall_number) = top_syscall_number_in_syscall_stack() {
        // syscallの入口だった場合
        if top_syscall_number != syscall_info.number {
            println!(
                "syscall enter: PID: {pid}, {:03}: {}",
                syscall_info.number, syscall_info.name
            );
            push_syscall_stack(syscall_info);
        }
        // syscallの出口だった場合
        else {
            if let Some(s) = pop_syscall_stack() {
                println!("syscall exit : {}", s.name);
            } else {
                panic!("syscall count failed");
            }
        }
    } else {
        println!(
            "syscall enter: PID: {pid}, {:03}: {}",
            syscall_info.number, syscall_info.name
        );
        push_syscall_stack(syscall_info);
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

    let regs = ptrace::getregs(pid);
    println!("{:x?}", regs);

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
    out_handle.write(b"> ").unwrap();
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
                } else {
                    if let Some(address) = find_breakpoint_address(bp, debug_info) {
                        address
                    } else {
                        return Err(Error::new(ErrorKind::NotFound, "breakpoint not found"));
                    }
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

static BREAKPOINTS: OnceCell<Mutex<BTreeMap<String, usize>>> = OnceCell::new();

fn init_breakpoints_map() {
    let _ = BREAKPOINTS.set(Mutex::new(BTreeMap::new()));
}

fn find_breakpoint_address(bp_str: &str, debug_info: &TdbDebugInfo) -> Option<usize> {
    debug_info::get_breakpoint_offset(bp_str, &debug_info.fn_info_vec)
}

unsafe fn set_breakpoint(child: Pid, addr: usize) -> Option<u8> {
    let read_long = ptrace::read(child, addr as *mut c_void);
    let read_long = match read_long {
        Ok(i) => i,
        Err(e) => {
            println!("failed to ptrace::read: {e}");
            return None;
        }
    };
    let mut read_long_vec = read_long.to_le_bytes();

    for l in read_long_vec {
        print!("0x{:02x} ", l);
    }
    println!("");

    let head = read_long_vec[0];

    read_long_vec[0] = 0xcc;

    let mut write_long = 0;
    for i in 0..(read_long_vec.len()) {
        write_long += (read_long_vec[i as usize] as u64) << (i * 8);
    }

    let write_ref = &write_long;

    if let Err(e) = ptrace::write(
        child,
        addr as *mut c_void,
        write_ref as *const _ as *mut c_void,
    ) {
        println!("failed to ptrace::write, {e}");
        return None;
    }

    Some(head)
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
fn dump_process_memory_info(child: Pid) {
    let maps = get_process_maps(child.as_raw()).unwrap();
    for map in maps {
        println!("{:x?}", map);
    }
}
