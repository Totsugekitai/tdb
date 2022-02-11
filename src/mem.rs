use nix::unistd::Pid;
use proc_maps::{get_process_maps, MapRange};
use std::{io, path::Path};

pub fn get_exec_segment_info(pid: Pid, filename: &str) -> Result<MapRange, io::Error> {
    let maps = get_process_maps(pid.as_raw()).unwrap();
    for map in maps {
        if map.is_exec() {
            let path_filename = map
                .filename()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap();

            let proc_filename = Path::new(filename).file_name().unwrap().to_str().unwrap();

            if path_filename == proc_filename {
                return Ok(map);
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "process not found"))
}
