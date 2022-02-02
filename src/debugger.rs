use crate::{
    dwarf::get_debug_info,
    syscall::{
        get_regs, get_syscall_info, init_syscall_stack, pop_syscall_stack, push_syscall_stack,
        top_syscall_number_in_syscall_stack,
    },
    DEBUGGER_NAME,
};
use nix::{
    libc::{PTRACE_O_TRACEEXEC, PTRACE_O_TRACESYSGOOD},
    sys::{
        ptrace,
        signal::Signal,
        uio::{process_vm_readv, IoVec, RemoteIoVec},
        wait::{
            waitpid, WaitPidFlag,
            WaitStatus::{
                Continued, Exited, PtraceEvent, PtraceSyscall, Signaled, StillAlive, Stopped,
            },
        },
    },
    unistd::Pid,
};
use proc_maps::get_process_maps;
use std::{
    io::{self, BufRead},
    process::exit,
};

pub fn debugger_main(child: Pid, filename: &str) {
    if let Err(e) = ptrace::attach(child) {
        panic!("ptrace::attach failed, errno: {e}");
    }

    get_debug_info(filename);
    init_syscall_stack();

    test_readv(child);

    loop {
        let wait_options =
            WaitPidFlag::from_bits(WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits());

        let status = waitpid(child, wait_options);

        let status = match status {
            Ok(status) => {
                let ptrace_options =
                    ptrace::Options::from_bits(PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD).unwrap();
                let _ = ptrace::setoptions(child, ptrace_options);
                status
            }
            Err(_e) => continue,
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

fn signaled(pid: Pid, signal: Signal, _core_dump: bool) {
    println!("signaled: PID: {pid}, Signal: {:?}", signal);
    if let Err(e) = ptrace::cont(pid, signal) {
        panic!("ptrace::syscall failed: errno = {e}");
    }
}

fn still_alive() {
    println!("still alive");
}

fn stopped(pid: Pid, signal: Signal) {
    println!("stopped: PID: {pid}, Signal: {:?}", signal);
    if let Err(e) = ptrace::cont(pid, signal) {
        panic!("ptrace::syscall failed: errno = {e}");
    }
}

#[allow(unused)]
fn intext() {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    let mut buf = String::new();
    handle.read_line(&mut buf).unwrap();

    println!("{buf}");
}

fn test_readv(pid: Pid) {
    let maps = get_process_maps(pid.as_raw()).unwrap();
    for map in maps {
        if map.is_exec() {
            let path_filename = map
                .filename()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap();
            if path_filename == DEBUGGER_NAME {
                println!(
                    "exec maps - pid: {pid}, name: {}, start: 0x{:x}",
                    map.filename().unwrap().as_os_str().to_str().unwrap(),
                    map.start()
                );
                let addr = map.start();
                let mut buf = vec![0xcc]; // int3
                let len = buf.len();
                let local_iov = IoVec::from_mut_slice(&mut buf);
                let remote_iov = RemoteIoVec { base: addr, len };
                if let Ok(num_bytes) = process_vm_readv(pid, &[local_iov], &[remote_iov]) {
                    println!("read {num_bytes} byte");
                    println!("data: {:x}", buf[0]);
                }
            }
        }
    }
}
