#[repr(C)]
#[derive(Debug)]
struct VmcallArgs {
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
}

impl Default for VmcallArgs {
    fn default() -> Self {
        Self {
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
struct VmcallRet {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
}

impl Default for VmcallRet {
    fn default() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
        }
    }
}

const GET_VMMCALL_NUMBER: u64 = 0;

#[repr(C)]
#[derive(Debug)]
pub struct VmcallStruct {
    vmcall_number: u64,
    arg: VmcallArgs,
    ret: VmcallRet,
}

extern "C" {
    fn vmcall_tdb(vmcall_struct: *mut VmcallStruct);
}

impl VmcallStruct {
    pub fn vmmcall_tdb(&mut self, phys: u64, len: u64) {
        self.arg.rbx = phys;
        self.arg.rcx = len;
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
        vmcall_struct.vmcall_number = GET_VMMCALL_NUMBER;
        vmcall_struct.arg.rbx = name.as_ptr() as *const u64 as u64;
        let vmcall_number = vmcall_struct.vmcall();
        vmcall_number
    }

    pub fn set_vmcall_number(&mut self, n: u64) {
        self.vmcall_number = n;
    }
}

impl Default for VmcallStruct {
    fn default() -> Self {
        Self {
            vmcall_number: 0,
            arg: VmcallArgs::default(),
            ret: VmcallRet::default(),
        }
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

    // pub fn exists(&self, addr: u64) -> bool {
    //     for vw in &self.vm_watchpoint {
    //         if vw.virt == addr {
    //             return true;
    //         }
    //     }
    //     false
    // }

    pub fn is_empty(&self) -> bool {
        self.vm_watchpoint.is_empty()
    }
}
