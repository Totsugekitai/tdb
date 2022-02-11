#![allow(unused)]
use nix::{libc::c_void, sys::ptrace, unistd::Pid};
use proc_maps::get_process_maps;

pub fn memory_map(pid: Pid) {
    let maps = get_process_maps(pid.as_raw()).unwrap();
    for map in maps {
        println!("{:x?}", map);
    }
}

const LONG_SIZE: u64 = 8;

pub fn memory(pid: Pid, addr: u64, len: u64) {
    let num = if (len % LONG_SIZE) == 0 {
        len / LONG_SIZE
    } else {
        len / LONG_SIZE + 1
    };
    for i in 0..num {
        let memdump = ptrace::read(pid, (addr + i * LONG_SIZE) as *mut c_void).unwrap();
        let memvec = memdump.to_le_bytes();
        for m in memvec {
            print!("{:02x} ", m);
        }
        println!();
    }
}

pub fn register(pid: Pid) {
    let regs = ptrace::getregs(pid);
    println!("{:x?}", regs);
}
