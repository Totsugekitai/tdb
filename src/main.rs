mod command_line;
mod debug_info;
mod debuggee;
mod debugger;
mod syscall;

use clap::StructOpt;
use command_line::Args;
use debuggee::debuggee_main;
use debugger::debugger_main;
use nix::{
    sys::personality::{self, Persona},
    unistd::{
        fork,
        ForkResult::{Child, Parent},
    },
};

pub const DEBUGGER_NAME: &str = "tdb";

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
