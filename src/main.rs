mod child;
mod command_line;
mod parent;
mod syscall;

use child::child_main;
use clap::StructOpt;
use command_line::Args;
use nix::unistd::{
    fork,
    ForkResult::{Child, Parent},
};
use parent::parent_main;

fn main() {
    let args = Args::parse();

    let pid = unsafe { fork() };
    let pid = match pid {
        Ok(fork_result) => fork_result,
        Err(e) => panic!("fork error: ERRNO = {e}"),
    };
    match pid {
        Parent { child } => parent_main(child),
        Child => child_main(&args.file, &args.args.iter().map(|s| &**s).collect()),
    }
}
