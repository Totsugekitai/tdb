#![allow(unused)]
use crate::{
    debug_info::{SymbolTrait, TdbDebugInfo},
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
        print!("0x{:016x}  ", addr + i * 8);

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
    let base_addr = debugger_info.debug_info.base_addr;
    let exec_map = debugger_info.debug_info.exec_maps().unwrap()[0]; // とりあえずコードセグメントが1つだけのバイナリに対応
    let base_diff = exec_map.start() as u64 - base_addr;
    let mut f_vec = Vec::new();
    for f in &debugger_info.debug_info.fn_info_vec {
        let exec_map_offset = exec_map.offset as u64;
        let addr = if f.offset() >= exec_map_offset {
            exec_map.start() as u64 + (f.offset() - exec_map_offset)
        } else {
            f.offset()
        };
        f_vec.push((addr, f.name()));
    }

    for f in f_vec {
        println!("0x{:016x}: {}", f.0, f.1);
    }
}

pub fn variables(debugger_info: &DebuggerInfo) {
    let base_addr = debugger_info.debug_info.base_addr;

    let rodata_maps = debugger_info.debug_info.rodata_maps().unwrap();
    for rodata_map in &rodata_maps {
        let base_diff = rodata_map.start() as u64 - base_addr;
        for v in &debugger_info.debug_info.var_info_vec {
            let rodata_map_offset = rodata_map.offset as u64;
            if v.is_included(rodata_map, base_addr) {
                let addr = if v.offset() > base_diff {
                    let var_offset = v.offset() - base_diff;
                    base_addr + var_offset
                } else {
                    v.offset()
                };
            }
        }
    }

    let data_maps = debugger_info.debug_info.data_maps().unwrap();
    for data_map in &data_maps {
        let base_diff = data_map.start() as u64 - base_addr;
        for v in &debugger_info.debug_info.var_info_vec {
            let data_map_offset = data_map.offset as u64;
            if v.is_included(data_map, base_addr) {
                let addr = if v.offset() > base_diff {
                    let var_offset = v.offset() - base_diff;
                    base_addr + var_offset
                } else {
                    v.offset()
                };
            }
        }
    }

    for var in &debugger_info.debug_info.var_info_vec {
        let name = Name::from(var.name());
        let name = name.try_demangle(DemangleOptions::name_only());
        if let Some(addr) = debugger_info.debug_info.get_actual_symbol_address(var) {
            println!("0x{:016x}: {}", addr, name);
        } else {
            println!("0x{:016x}: {}", 0, name);
        }
    }
}

pub fn backtrace(debug_info: &TdbDebugInfo) {
    let regs = get_regs(debug_info.target_pid);
    let rbp = regs.rbp;
    let rip = regs.rip;
    if let Some(f) = debug_info.find_function_in(rip) {
        println!("0x{:016x} in {}(top)", rip, f.name());
        backtrace_inner(debug_info, rbp).unwrap();
    }
}

fn backtrace_inner(debug_info: &TdbDebugInfo, rbp: u64) -> Result<(), Box<dyn std::error::Error>> {
    let prev_frame_addr = ptrace::read(debug_info.target_pid, rbp as *mut c_void)? as u64;
    let return_addr = ptrace::read(debug_info.target_pid, (rbp + 8) as *mut c_void)? as u64;
    if let Some(f) = debug_info.find_function_in(return_addr) {
        backtrace_inner(debug_info, prev_frame_addr)?;
        println!("0x{:016x} in {}", return_addr, f.name());
    } else {
        let regs = get_regs(debug_info.target_pid);
        let rsp = regs.rsp;
        let return_addr = ptrace::read(debug_info.target_pid, rsp as *mut c_void)? as u64;
        if let Some(f) = debug_info.find_function_in(return_addr) {
            println!("0x{:016x} in {}", return_addr, f.name());
        }
    }
    Ok(())
}
