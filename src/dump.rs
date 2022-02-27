#![allow(unused)]
use crate::{
    debug_info::{Symbol, TdbDebugInfo, TdbMapRangeTrait},
    debugger::DebuggerInfo,
    syscall::get_regs,
};
use nix::{libc::c_void, sys::ptrace, unistd::Pid};
use object::Endian;
use proc_maps::get_process_maps;
use std::{borrow::Borrow, path::Path};
use symbolic::{
    common::Name,
    demangle::{demangle, Demangle, DemangleOptions},
};

pub fn memory_map(pid: Pid) {
    let maps = get_process_maps(pid.as_raw()).unwrap();
    for map in maps {
        println!(
            "0x{:016x}-0x{:016x}, off: 0x{:08x}, flags: {}, file: {}",
            map.start(),
            map.start() + map.size(),
            map.offset,
            map.flags,
            map.filename()
                .unwrap_or_else(|| Path::new(""))
                .to_str()
                .unwrap()
        );
        let virt_start = map.start() as u64;
        crate::debugger::print_physaddr(pid, virt_start);
    }
}

const LONG_SIZE: u64 = 8;

pub fn memory(debug_info: &TdbDebugInfo, addr: u64, len: u64) {
    let num = if (len % LONG_SIZE) == 0 {
        len / LONG_SIZE
    } else {
        len / LONG_SIZE + 1
    };
    'outer: for i in 0..num {
        let actual_addr = addr + i * LONG_SIZE;
        for map in debug_info.mmaps() {
            if map.is_included(actual_addr) {
                memory_inner(debug_info, actual_addr);
                continue 'outer;
            }
        }
        println!("out of memory map, memory dump interrupted.");
        break;
    }
}

fn memory_inner(debug_info: &TdbDebugInfo, actual_addr: u64) {
    print!("0x{:016x}  ", actual_addr);

    let memdump = ptrace::read(debug_info.target_pid(), actual_addr as *mut c_void).unwrap();
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

pub fn register(pid: Pid) {
    let regs = ptrace::getregs(pid).unwrap();
    println!("r15: 0x{:016x?}", regs.r15);
    println!("r14: 0x{:016x?}", regs.r14);
    println!("r13: 0x{:016x?}", regs.r13);
    println!("r12: 0x{:016x?}", regs.r12);
    println!("r11: 0x{:016x?}", regs.r11);
    println!("r10: 0x{:016x?}", regs.r10);
    println!("r9 : 0x{:016x?}", regs.r9);
    println!("r8 : 0x{:016x?}", regs.r8);
    println!("rax: 0x{:016x?}", regs.rax);
    println!("rbx: 0x{:016x?}", regs.rbx);
    println!("rcx: 0x{:016x?}", regs.rcx);
    println!("rdx: 0x{:016x?}", regs.rdx);
    println!("rsi: 0x{:016x?}", regs.rsi);
    println!("rdi: 0x{:016x?}", regs.rdi);
    println!("rip: 0x{:016x?}", regs.rip);
    println!("rsp: 0x{:016x?}", regs.rsp);
    println!("rbp: 0x{:016x?}", regs.rbp);
    println!("cs : 0x{:016x?}", regs.cs);
    println!("ds : 0x{:016x?}", regs.ds);
    println!("es : 0x{:016x?}", regs.es);
    println!("fs : 0x{:016x?}", regs.fs);
    println!("gs : 0x{:016x?}", regs.gs);
    println!("ss : 0x{:016x?}", regs.ss);
    println!("fs_base: 0x{:016x?}", regs.fs);
    println!("gs_base: 0x{:016x?}", regs.gs);
    println!("orig_rax: 0x{:016x?}", regs.orig_rax);
    println!("eflags: 0x{:016x?}", regs.eflags);
}

pub fn all_symbols(debugger_info: &DebuggerInfo) {
    println!("[functions]");
    functions(debugger_info);
    println!();
    println!("[variables]");
    variables(debugger_info);
}

pub fn functions(debugger_info: &DebuggerInfo) {
    let base_addr = debugger_info.debug_info.base_addr();
    let exec_map = debugger_info.debug_info.exec_maps().unwrap()[0]; // とりあえずコードセグメントが1つだけのバイナリに対応
    let base_diff = exec_map.start() as u64 - base_addr;
    let mut f_vec = Vec::new();
    for f in debugger_info.debug_info.symbols() {
        let exec_map_offset = exec_map.offset as u64;
        let addr = if f.address() >= exec_map_offset {
            exec_map.start() as u64 + (f.address() - exec_map_offset)
        } else {
            f.address()
        };
        f_vec.push((addr, f.name()));
    }

    for f in f_vec {
        println!("0x{:016x}: {}", f.0, f.1);
    }
}

pub fn variables(debugger_info: &DebuggerInfo) {
    let base_addr = debugger_info.debug_info.base_addr();

    let rodata_maps = debugger_info.debug_info.rodata_maps().unwrap();
    for rodata_map in &rodata_maps {
        let base_diff = rodata_map.start() as u64 - base_addr;
        for v in debugger_info.debug_info.symbols() {
            let rodata_map_offset = rodata_map.offset as u64;
            // if v.is_included(rodata_map, base_addr) {
            //     let addr = if v.address() > base_diff {
            //         let var_offset = v.address() - base_diff;
            //         base_addr + var_offset
            //     } else {
            //         v.address()
            //     };
            // }
        }
    }

    let data_maps = debugger_info.debug_info.data_maps().unwrap();
    for data_map in &data_maps {
        let base_diff = data_map.start() as u64 - base_addr;
        for v in debugger_info.debug_info.symbols() {
            let data_map_offset = data_map.offset as u64;
            // if v.is_included(data_map, base_addr) {
            //     let addr = if v.address() > base_diff {
            //         let var_offset = v.address() - base_diff;
            //         base_addr + var_offset
            //     } else {
            //         v.address()
            //     };
            // }
        }
    }

    for var in debugger_info.debug_info.symbols() {
        let name = Name::from(var.name());
        let name = name.try_demangle(DemangleOptions::name_only());
        if let Some(addr) = debugger_info.debug_info.get_actual_symbol_address(var) {
            println!("0x{:016x}: {}", addr, name);
        } else {
            println!("0x{:016x}: {}", 0, name);
        }
    }
}

pub fn misc_symbols(debug_info: &TdbDebugInfo) {
    for misc in debug_info.symbols() {
        println!("{:x?}", misc);
    }
}

pub fn backtrace(debug_info: &TdbDebugInfo) {
    let regs = get_regs(debug_info.target_pid());
    let rbp = regs.rbp;
    let rip = regs.rip;
    if let Some(f) = debug_info.find_function_in(rip) {
        println!("0x{:016x} in {}(top)", rip, f.name());
        backtrace_inner(debug_info, rbp).unwrap();
    }
}

fn backtrace_inner(debug_info: &TdbDebugInfo, rbp: u64) -> Result<(), Box<dyn std::error::Error>> {
    let prev_frame_addr = ptrace::read(debug_info.target_pid(), rbp as *mut c_void)? as u64;
    let return_addr = ptrace::read(debug_info.target_pid(), (rbp + 8) as *mut c_void)? as u64;
    if let Some(f) = debug_info.find_function_in(return_addr) {
        // このコードブロックは、関数突入直後のスタックフレームが構築される前でも関数を表示したいために入れている
        {
            let rsp = get_regs(debug_info.target_pid()).rsp;
            let tmp_frame_addr = ptrace::read(debug_info.target_pid(), rsp as *mut c_void)? as u64;
            if let Some(f) = debug_info.find_function_in(tmp_frame_addr) {
                println!("0x{:016x} in {}", tmp_frame_addr, f.name());
            }
        }

        println!("0x{:016x} in {}", return_addr, f.name());
        backtrace_inner(debug_info, prev_frame_addr)?;
    }
    Ok(())
}

pub fn watchpoints(debugger_info: &DebuggerInfo) {
    for w in &debugger_info.watch_list {
        println!("{:016x?}", w);
    }
}
