use nix::unistd::Pid;
use proc_maps::{get_process_maps, MapRange};
use std::{io, path::Path};

// pub fn get_exec_segment_info(pid: Pid, filename: &str) -> Result<MapRange, io::Error> {
//     let maps = get_process_maps(pid.as_raw()).unwrap();
//     for map in maps {
//         if map.is_exec() {
//             let path_filename = map
//                 .filename()
//                 .unwrap()
//                 .file_name()
//                 .unwrap()
//                 .to_str()
//                 .unwrap();

//             let proc_filename = Path::new(filename).file_name().unwrap().to_str().unwrap();

//             if path_filename == proc_filename {
//                 return Ok(map);
//             }
//         }
//     }
//     Err(io::Error::new(io::ErrorKind::NotFound, "process not found"))
// }

/// 一番アドレスが小さい場所にあるセグメントを取ってくる
pub fn get_bottom_segment_info(pid: Pid, filename: &str) -> Result<MapRange, io::Error> {
    let maps = get_process_maps(pid.as_raw()).unwrap();
    let mut bottom_segment = (u64::MAX, None); // 一番アドレスが小さいセグメント
    for map in maps {
        let path_filename = map.filename();

        if let Some(path_filename) = path_filename {
            let path_filename = path_filename.file_name().unwrap().to_str().unwrap();

            let proc_filename = Path::new(filename).file_name().unwrap().to_str().unwrap();

            if path_filename == proc_filename && (map.start() as u64) < bottom_segment.0 {
                bottom_segment.0 = map.start() as u64;
                bottom_segment.1 = Some(map);
            }
        }
    }
    if let Some(m) = bottom_segment.1 {
        Ok(m)
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "process not found"))
    }
}
