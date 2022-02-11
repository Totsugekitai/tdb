use nix::{
    libc::{c_void, user_regs_struct},
    sys::ptrace,
    unistd::Pid,
};

#[derive(Debug)]
pub struct Breakpoint {
    pub addr: u64,
    pub value: u8,
}

impl Breakpoint {
    pub fn new(addr: u64, value: u8) -> Self {
        Self { addr, value }
    }

    pub fn restore_memory(
        &self,
        pid: Pid,
        regs: user_regs_struct,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("breakpoint!");
        let data = ptrace::read(pid, self.addr as *const c_void as *mut c_void).unwrap();
        let mut data_vec = data.to_le_bytes();
        if data_vec[0] == 0xcc {
            data_vec[0] = self.value;
        } else {
            panic!(
                "bad breakpoint! addr: 0x{:x}, value: 0x{:x}",
                self.addr, data_vec[0]
            );
        }
        let mut data_long = 0;
        for i in 0..(data_vec.len()) {
            data_long += (data_vec[i as usize] as u64) << (i * 8);
        }
        unsafe {
            ptrace::write(
                pid,
                self.addr as *const c_void as *mut c_void,
                data_long as *mut c_void,
            )
            .unwrap();
        }
        let mut regs = regs;
        regs.rip = self.addr;
        ptrace::setregs(pid, regs).unwrap();
        Ok(())
    }
}

#[derive(Debug)]
pub struct BreakpointManager {
    pid: Pid,
    breakpoints: Vec<Breakpoint>,
}

impl BreakpointManager {
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            breakpoints: Vec::new(),
        }
    }

    /// set breakpoint
    pub fn set(&mut self, addr: u64) -> Result<u8, Box<dyn std::error::Error>> {
        let read = ptrace::read(self.pid, addr as *mut c_void)?;
        let mut read_vec = read.to_le_bytes();

        let head = read_vec[0];

        read_vec[0] = 0xcc;

        let mut write = 0;
        for i in 0..(read_vec.len()) {
            write += (read_vec[i as usize] as u64) << (i * 8);
        }

        let _ = unsafe { ptrace::write(self.pid, addr as *mut c_void, write as *mut c_void)? };

        self.breakpoints.push(Breakpoint::new(addr, head));

        Ok(head)
    }

    /// get breakpoint value if exists
    pub fn get(&self, addr: u64) -> Option<&Breakpoint> {
        for breakpoint in &self.breakpoints {
            if addr == breakpoint.addr {
                return Some(breakpoint);
            }
        }
        None
    }
}
