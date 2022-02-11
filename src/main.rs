mod args;
mod breakpoint;
mod debug_info;
mod debuggee;
mod debugger;
mod syscall;

use args::Args;
use clap::StructOpt;
use debuggee::debuggee_main;
use debugger::debugger_main;
use nix::{
    sys::personality::{self, Persona},
    unistd::{
        fork,
        ForkResult::{Child, Parent},
    },
};

fn main() {
    let args = Args::parse();

    let pers = personality::get().unwrap();
    if let Err(e) = personality::set(pers | Persona::ADDR_NO_RANDOMIZE) {
        panic!("failed to disable ASLR {e}");
    }

    let pid = unsafe { fork() };
    let pid = match pid {
        Ok(fork_result) => fork_result,
        Err(e) => panic!("fork error: ERRNO = {e}"),
    };
    match pid {
        Parent { child } => debugger_main(child, &args.file),
        Child => debuggee_main(
            &args.file,
            &args.args.iter().map(|s| &**s).collect::<Vec<&str>>(),
        ),
    }
}
