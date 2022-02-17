use nix::{sys::ptrace, unistd::execvp};
use std::{
    ffi::{CStr, CString},
    fs,
    path::Path,
};

#[derive(Debug)]
pub struct DebuggeeInfo {}

pub fn target_main(path: &Path, args: &[&str]) {
    let _ = ptrace::traceme();
    let cstr = path_to_cstr(path);

    let mut args_cstr = vec![];
    for arg in args {
        args_cstr.push(str_to_cstr(arg));
    }

    // argsが空の場合は空文字列を入れる
    if args.is_empty() {
        args_cstr.push(str_to_cstr(""));
    }

    let _ = execvp(&cstr, &args_cstr);
    println!("execvp error!");
}

fn str_to_cstr(s: &str) -> Box<CStr> {
    let mut s_u8_vec = vec![];
    for b in s.as_bytes() {
        s_u8_vec.push(*b);
    }
    s_u8_vec.push(b'\0');
    let c_string = CString::from_vec_with_nul(s_u8_vec).expect("CString::from_vec_with_nul failed");
    c_string.into_boxed_c_str()
}

fn path_to_cstr(path: &Path) -> Box<CStr> {
    let mut s_u8_vec = vec![];
    for b in fs::canonicalize(path) // 絶対パスを取得
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
        .as_bytes()
    {
        s_u8_vec.push(*b);
    }
    s_u8_vec.push(b'\0');
    let c_string = CString::from_vec_with_nul(s_u8_vec).expect("CString::from_vec_with_nul failed");
    c_string.into_boxed_c_str()
}
