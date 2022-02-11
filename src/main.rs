mod args;
mod breakpoint;
mod command;
mod debug_info;
mod debugger;
mod dump;
mod mem;
mod signal;
mod syscall;
mod target;

use std::path::Path;

use args::Args;
use clap::StructOpt;
use debugger::debugger_main;
use nix::{
    sys::personality::{self, Persona},
    unistd::{
        fork,
        ForkResult::{Child, Parent},
    },
};
use target::target_main;

fn main() {
    let args = Args::parse();
    args.print_info();

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
        Child => target_main(
            Path::new(&args.file),
            &args.args.iter().map(|s| &**s).collect::<Vec<&str>>(),
        ),
    }
}
