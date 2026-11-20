use std::{env, path::PathBuf};

fn main() {
    let amr = pkg_config::probe_library("opencore-amrnb")
        .expect("install the OpenCORE AMR-NB development package");
    let bindings = bindgen::Builder::default()
        .header_contents(
            "amrnb.h",
            "#include <opencore-amrnb/interf_enc.h>\n#include <opencore-amrnb/interf_dec.h>",
        )
        .clang_args(
            amr.include_paths
                .iter()
                .map(|path| format!("-I{}", path.display())),
        )
        .allowlist_function("(Encoder|Decoder)_Interface_.*")
        .generate_comments(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("generate OpenCORE AMR-NB bindings");
    bindings
        .write_to_file(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("amr.rs"))
        .expect("write OpenCORE AMR-NB bindings");
}
