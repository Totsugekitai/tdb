use nix::{libc::c_void, sys::ptrace, unistd::Pid};
use proc_maps::{get_process_maps, MapRange};
use std::{io, path::Path};

pub fn get_mmap_info(pid: Pid, filename: &str) -> Result<Vec<MapRange>, io::Error> {
    let proc_filename = Path::new(filename).file_name().unwrap().to_str().unwrap();
    let maps = get_process_maps(pid.as_raw()).unwrap();
    let mut is_file_mapped = false;

    for map in &maps {
        let path_filename = map.filename();

        if let Some(path_filename) = path_filename {
            let path_filename = path_filename.file_name().unwrap().to_str().unwrap();

            if path_filename == proc_filename {
                is_file_mapped = true;
            }
        }
    }

    if is_file_mapped {
        Ok(maps)
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "process not found"))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Memory {
    pub addr: u64,
    pub value: u64,
}

impl Memory {
    pub fn write_value(&self, pid: Pid) {
        unsafe {
            ptrace::write(pid, self.addr as *mut c_void, self.value as *mut c_void).unwrap();
        }
    }
}
