use libc::c_void;
use nix::{sys::ptrace, unistd::Pid};

#[derive(Debug)]
pub struct Breakpoint {
    addr: u64,
    value: u8,
}

impl Breakpoint {
    pub fn new(addr: u64, value: u8) -> Self {
        Self { addr, value }
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
    pub fn get(&self, addr: u64) -> Option<u8> {
        for breakpoint in &self.breakpoints {
            if addr == breakpoint.addr {
                return Some(breakpoint.value);
            }
        }
        None
    }
}
