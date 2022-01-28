mod child;
mod parent;
use child::child_main;
use nix::unistd::{
    fork,
    ForkResult::{Child, Parent},
};
use parent::parent_main;

fn main() {
    let pid = unsafe { fork() };
    let pid = match pid {
        Ok(fork_result) => fork_result,
        Err(e) => panic!("fork error: ERRNO = {e}"),
    };
    match pid {
        Parent { child } => parent_main(child),
        Child => child_main("/bin/ls", &vec!["-a", "-l"]),
    }
}
