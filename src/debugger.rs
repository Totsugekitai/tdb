use std::{
    fmt::Debug,
    io::{Read, Seek},
};

#[allow(unused)]
use crate::{
    breakpoint::BreakpointManager,
    command::Command,
    debug_info::{self, TdbDebugInfo},
    dump, mem, register,
    syscall::{get_regs, SyscallInfo, SyscallStack},
};
use nix::{libc::c_void, sys::ptrace, unistd::Pid};
use std::process::exit;

#[derive(Debug)]
pub struct DebuggerInfo {
    pub syscall_stack: SyscallStack,
    pub breakpoint_manager: BreakpointManager,
    pub vm_watchpoint_manager: crate::call_vmm::VmWatchpointManager,
    pub debug_info: TdbDebugInfo,
    pub prev_command: Option<crate::command::Command>,
    pub watch_list: Vec<WatchPoint>,
    pub cont_flag: bool,
}

impl DebuggerInfo {
    pub fn set_watchpoint(&mut self, watchpoint: WatchPoint) {
        self.watch_list.push(watchpoint);
    }
}

#[derive(Debug)]
pub enum WatchPoint {
    Memory(mem::Memory),
    Register(register::Register),
}

impl WatchPoint {
    fn get_value(&self) -> u64 {
        match *self {
            Self::Memory(m) => m.value,
            Self::Register(r) => r.value,
        }
    }

    fn update_value(&mut self, value: u64) -> u64 {
        match self {
            Self::Memory(mem) => {
                let old = mem.value;
                mem.value = value;
                old
            }
            Self::Register(reg) => {
                let old = reg.value;
                reg.value = value;
                old
            }
        }
    }

    fn is_changed(&self, pid: Pid) -> bool {
        match *self {
            Self::Memory(mem) => {
                let read = ptrace::read(pid, mem.addr as *mut c_void).unwrap() as u64;
                mem.value != read
            }
            Self::Register(reg) => {
                let read = reg.reg_type.get_current_value(pid);
                reg.value != read
            }
        }
    }

    fn fetch_new_value(&self, pid: Pid) -> u64 {
        match *self {
            Self::Memory(mem) => ptrace::read(pid, mem.addr as *mut c_void).unwrap() as u64,
            Self::Register(reg) => reg.reg_type.get_current_value(pid),
        }
    }
}

pub fn print_physaddr(pid: Pid, virt: u64) {
    let mut pagemap = std::fs::File::open(format!("/proc/{}/pagemap", pid.as_raw())).unwrap();
    let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .unwrap()
        .unwrap() as u64;
    let virt_pfn = virt / page_size; // PFN = Page Frame Number
    let offset = virt_pfn * 8;
    pagemap.seek(std::io::SeekFrom::Start(offset)).unwrap();
    let mut page_buf = [0u8; 8];
    let _ = pagemap.read_exact(&mut page_buf).unwrap();

    let page = u64::from_le_bytes(page_buf);

    let page = ((page & 0x7fffffffffffffu64) * page_size) + (virt % page_size);

    println!("PhysPage: 0x{:x}", page);
}

pub fn virt2phys(pid: Pid, virt: u64) -> u64 {
    let mut pagemap = std::fs::File::open(format!("/proc/{}/pagemap", pid.as_raw())).unwrap();
    let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .unwrap()
        .unwrap() as u64;
    let virt_pfn = virt / page_size; // PFN = Page Frame Number
    let offset = virt_pfn * 8;
    pagemap.seek(std::io::SeekFrom::Start(offset)).unwrap();
    let mut page_buf = [0u8; 8];
    let _ = pagemap.read_exact(&mut page_buf).unwrap();

    let page = u64::from_le_bytes(page_buf);

    if (page & 0x8000_0000_0000_0000u64) == 0 {
        println!("page not present");
    }

    ((page & 0x007fffffffffffffu64) * page_size) + (virt % page_size)
}

pub fn debugger_main(child: Pid, filename: &str) {
    if let Err(e) = ptrace::attach(child) {
        panic!("ptrace::attach failed, errno: {e}");
    }

    // init
    crate::signal::init(child);
    let mut syscall_stack = SyscallStack::new();
    let breakpoint_manager = BreakpointManager::new(child);
    let (debug_info, status) = TdbDebugInfo::init(filename, child, &mut syscall_stack);
    let mut debugger_info = DebuggerInfo {
        syscall_stack,
        breakpoint_manager,
        vm_watchpoint_manager: crate::call_vmm::VmWatchpointManager::new(),
        debug_info,
        watch_list: Vec::new(),
        prev_command: None,
        cont_flag: false,
    };

    let mut status = status;
    let mut additional_command = None;
    loop {
        if let Some(command) = additional_command {
            let exec_return = Command::exec(command, &mut debugger_info, status);
            match exec_return {
                Ok(exec_return) => {
                    status = exec_return.0;
                    additional_command = exec_return.1;
                }
                Err(e) => {
                    println!("{:?}", e);
                    exit(0);
                }
            }
        } else {
            let command = match Command::read(&mut debugger_info) {
                Ok(command) => command,
                Err(e) => {
                    println!("{e}");
                    continue;
                }
            };

            let exec_return = Command::exec(command, &mut debugger_info, status);
            match exec_return {
                Ok(exec_return) => {
                    status = exec_return.0;
                    additional_command = exec_return.1;
                }
                Err(e) => {
                    println!("{:?}", e);
                    exit(0);
                }
            }
        }
        // ウォッチポイントのチェック
        check_watchpoints(&mut debugger_info, &mut additional_command);
    }
}

pub fn check_watchpoints(
    debugger_info: &mut DebuggerInfo,
    additional_command: &mut Option<Command>,
) {
    for w in &mut debugger_info.watch_list {
        if w.is_changed(debugger_info.debug_info.target_pid()) {
            debugger_info.cont_flag = false;
            *additional_command = None;
            let new = w.fetch_new_value(debugger_info.debug_info.target_pid());
            let old = w.update_value(new);
            println!("{:x?}: 0x{:x} -> 0x{:x}", w, old, w.get_value());
        }
    }
}

pub fn catch_syscall(pid: Pid, syscall_stack: &mut SyscallStack) {
    let syscall_info = SyscallInfo::from_regs(&get_regs(pid));

    if let Some(top) = syscall_stack.top() {
        // syscallの入口だった場合
        if top.number() != syscall_info.number() {
            syscall_stack.push(syscall_info);
        }
        // syscallの出口だった場合
        else if syscall_stack.pop().is_none() {
            panic!("syscall count failed");
        }
    } else {
        syscall_stack.push(syscall_info);
    }

    if let Err(e) = ptrace::syscall(pid, None) {
        panic!("ptrace::syscall failed: errno = {:?}", e);
    }
}
