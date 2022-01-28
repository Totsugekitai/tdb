use std::process::exit;

use nix::{
    libc::{PTRACE_O_TRACEEXEC, PTRACE_O_TRACESYSGOOD},
    sys::{
        ptrace,
        signal::Signal,
        wait::{
            waitpid, WaitPidFlag,
            WaitStatus::{
                Continued, Exited, PtraceEvent, PtraceSyscall, Signaled, StillAlive, Stopped,
            },
        },
    },
    unistd::Pid,
};

pub fn parent_main(child: Pid) {
    if let Err(e) = ptrace::attach(child) {
        panic!("ptrace::attach failed, errno: {e}");
    }

    let ptrace_options =
        ptrace::Options::from_bits(PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD).unwrap();
    ptrace::setoptions(child, ptrace_options).unwrap();

    loop {
        let wait_options =
            WaitPidFlag::from_bits(WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits());

        let status = waitpid(child, wait_options);

        let status = match status {
            Ok(status) => status,
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
    println!("continued! PID: {pid}");
}

fn exited(pid: Pid, exit_code: i32) {
    println!("exited!: PID: {pid}, exit code: {exit_code}");
    exit(exit_code);
}

fn ptrace_event(pid: Pid, signal: Signal, event: i32) {
    println!("evented!: PID: {pid}, Signal: {:?}, Event: {event}", signal);
    if let Err(e) = ptrace::syscall(pid, None) {
        panic!("ptrace::syscall failed: errno = {:?}", e);
    }
}

fn ptrace_syscall(pid: Pid) {
    println!("syscall!: PID: {pid}");
    if let Err(e) = ptrace::syscall(pid, None) {
        panic!("ptrace::syscall failed: errno = {:?}", e);
    }
}

fn signaled(pid: Pid, signal: Signal, _core_dump: bool) {
    println!("signaled!: PID: {pid}, Signal: {:?}", signal);
    if let Err(e) = ptrace::syscall(pid, signal) {
        panic!("ptrace::syscall failed: errno = {e}");
    }
}

fn still_alive() {
    println!("still alive!");
}

fn stopped(pid: Pid, signal: Signal) {
    println!("stopped!: PID: {pid}, Signal: {:?}", signal);
    if let Err(e) = ptrace::syscall(pid, signal) {
        panic!("ptrace::syscall failed: errno = {e}");
    }
}
