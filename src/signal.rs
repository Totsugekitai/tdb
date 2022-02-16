use nix::{
    libc,
    sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal},
    unistd::Pid,
};
use once_cell::sync::OnceCell;
use std::{process::exit, sync::Mutex};

static CHILD_PID: OnceCell<Mutex<Pid>> = OnceCell::new();

extern "C" fn sigint_handler(_signum: libc::c_int) {
    let child_pid = CHILD_PID.get().unwrap().lock().unwrap();
    let _kr = signal::kill(*child_pid, Signal::SIGKILL);
    println!("kbd interrupt");
    exit(0);
}

fn init_child_pid(child: Pid) {
    CHILD_PID.set(Mutex::new(child)).unwrap();
}

fn init_handler() {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGINT);
    let handler = SigHandler::Handler(sigint_handler);
    let sigaction = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
    let _sigaction = unsafe { signal::sigaction(Signal::SIGINT, &sigaction) };
}

pub fn init(pid: Pid) {
    init_child_pid(pid);
    init_handler();
}
