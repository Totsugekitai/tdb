#![allow(unused)]
use std::path::Path;

use nix::{libc::c_void, sys::ptrace, unistd::Pid};
use proc_maps::get_process_maps;

use crate::debugger::DebuggerInfo;

pub fn memory_map(pid: Pid) {
    let maps = get_process_maps(pid.as_raw()).unwrap();
    for map in maps {
        println!(
            "0x{:016x}-0x{:016x}, off: 0x{:08x}, flags: {}, file: {}",
            map.start(),
            map.start() + map.size(),
            map.offset,
            map.flags,
            map.filename().unwrap_or(&Path::new("")).to_str().unwrap()
        );
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
        print!("{:016x}  ", addr + i * 8);

        let memdump = ptrace::read(pid, (addr + i * LONG_SIZE) as *mut c_void).unwrap();
        let memvec = memdump.to_le_bytes();
        for m in memvec {
            print!("{:02x} ", m);
        }

        print!(" |");
        for m in memvec {
            let c = if m.is_ascii() && (0x20 < m) && (m < 0x7f) {
                m
            } else {
                b'.'
            };
            print!("{}", c as char);
        }
        print!("|");

        println!();
    }
}

pub fn register(pid: Pid) {
    let regs = ptrace::getregs(pid);
    println!("{:x?}", regs);
}

pub fn symbols(debugger_info: &DebuggerInfo) {
    println!("functions:");
    for f in &debugger_info.debug_info.fn_info_vec {
        println!("0x{:016x}: {}", debugger_info.base_addr + f.offset, f.name);
    }

    println!();

    println!("variables:");
    for v in &debugger_info.debug_info.var_info_vec {
        println!("0x{:016x}: {}", v.offset, v.name);
    }
}
