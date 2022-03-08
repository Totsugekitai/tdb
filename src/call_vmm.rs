use nix::unistd::Pid;

#[repr(C)]
#[derive(Debug, Default)]
struct VmcallArgs {
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct VmcallRet {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct VmcallStruct {
    vmcall_number: u64,
    arg: VmcallArgs,
    ret: VmcallRet,
}

extern "C" {
    fn vmcall_tdb(vmcall_struct: *mut VmcallStruct);
}

impl VmcallStruct {
    pub fn vmcall_register(&mut self, phys: u64, len: u64) {
        self.arg.rbx = phys;
        self.arg.rcx = len;
        let ptr = self as *mut VmcallStruct;
        unsafe {
            vmcall_tdb(ptr);
        }
        println!("{:x?}", self);
    }

    pub fn vmcall_unregister(&mut self, phys: u64) {
        self.arg.rbx = phys;
        self.arg.rdi = 1;
        let ptr = self as *mut VmcallStruct;
        unsafe {
            vmcall_tdb(ptr);
        }
        println!("{:x?}", self);
    }

    fn vmcall(&mut self) -> u64 {
        let ptr = self as *mut VmcallStruct;
        unsafe {
            vmcall_tdb(ptr);
        }
        println!("{:x?}", self);
        self.ret.rax
    }

    pub fn get_function(name: std::ffi::CString) -> u64 {
        let mut vmcall_struct = Self::default();
        vmcall_struct.arg.rbx = name.as_ptr() as *const u64 as u64;
        vmcall_struct.vmcall()
    }

    pub fn set_vmcall_number(&mut self, n: u64) {
        self.vmcall_number = n;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VmWatchpoint {
    virt: u64,
    len: u64,
}

impl VmWatchpoint {
    pub fn new(virt: u64, len: u64) -> Self {
        Self { virt, len }
    }

    pub fn virt(&self) -> u64 {
        self.virt
    }

    pub fn len(&self) -> u64 {
        self.len
    }
}

#[derive(Debug)]
pub struct VmWatchpointManager {
    vm_watchpoint: Vec<VmWatchpoint>,
}

impl VmWatchpointManager {
    pub fn new() -> Self {
        Self {
            vm_watchpoint: Vec::new(),
        }
    }

    pub fn set(&mut self, vm_watchpoint: VmWatchpoint) {
        self.vm_watchpoint.push(vm_watchpoint);
    }

    pub fn delete_all(&self, pid: Pid) {
        for vw in &self.vm_watchpoint {
            let mut vmcall_struct = crate::call_vmm::VmcallStruct::default();
            let phys = crate::debugger::virt2phys(pid, vw.virt());
            vmcall_struct.vmcall_unregister(phys);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.vm_watchpoint.is_empty()
    }
}
