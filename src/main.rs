mod command_line;
mod debuggee;
mod debugger;
mod dwarf;
mod syscall;

use clap::StructOpt;
use command_line::Args;
use debuggee::debuggee_main;
use debugger::debugger_main;
use nix::unistd::{
    fork,
    ForkResult::{Child, Parent},
};

fn main() {
    let args = Args::parse();

    let pid = unsafe { fork() };
    let pid = match pid {
        Ok(fork_result) => fork_result,
        Err(e) => panic!("fork error: ERRNO = {e}"),
    };
    match pid {
        Parent { child } => debugger_main(child, &args.file),
        Child => debuggee_main(&args.file, &args.args.iter().map(|s| &**s).collect()),
    }
}
