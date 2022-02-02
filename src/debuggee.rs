use nix::{sys::ptrace::traceme, unistd::execvp};
use std::ffi::{CStr, CString};

#[derive(Debug)]
pub struct DebuggeeInfo {}

pub fn debuggee_main(filename: &str, args: &Vec<&str>) {
    let _ = traceme();
    let cstr = convert_string_ref_to_cstr_ref(filename);

    let mut args_cstr = vec![];
    for arg in args {
        args_cstr.push(convert_string_ref_to_cstr_ref(arg));
    }

    // argsが空の場合は空文字列を入れる
    if args.is_empty() {
        args_cstr.push(convert_string_ref_to_cstr_ref(""));
    }

    let _ = execvp(&cstr, &args_cstr);
    println!("execvp error!");
}

fn convert_string_ref_to_cstr_ref(s: &str) -> Box<CStr> {
    let mut s_u8_vec = vec![];
    for b in s.as_bytes() {
        s_u8_vec.push(b.clone());
    }
    s_u8_vec.push('\0' as u8);
    let c_string = CString::from_vec_with_nul(s_u8_vec).expect("CString::from_vec_with_nul failed");
    c_string.into_boxed_c_str()
}
