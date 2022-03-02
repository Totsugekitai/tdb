// use std::env;
// use std::path::PathBuf;

fn main() {
    cc::Build::new()
        .warnings(true)
        .file("src/call_vmm.S")
        .compile("libcall_vmm.a");

    // let bindings = bindgen::Builder::default()
    //     .header("src/c/call_vmm.h")
    //     .generate()
    //     .expect("Unable to generate bindings");

    // let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // bindings
    //     .write_to_file(out_path.join("bindings.rs"))
    //     .expect("Couldn't write bindings");
}
