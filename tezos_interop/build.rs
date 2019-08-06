use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run_builder(lib_dir: &PathBuf) {
    let build_chain = env::var("OCAML_BUILD_CHAIN").unwrap_or("local".to_string());

    match build_chain.as_ref() {
        "local" => {
            Command::new("opam")
                .args(&["config", "exec", "make"])
                .current_dir(lib_dir)
                .status()
                .expect("Couldn't run builder. Do you have opam and dune installed on your machine?");
        }
        "docker" => {
            Command::new("docker")
                .args(&["build", "-t", "lib_ocaml", "."])
                .current_dir("lib_ocaml")
                .status()
                .expect("Couldn't run docker build.");

            let lib_dir_absolute_path = fs::canonicalize(lib_dir).unwrap();
            Command::new("docker")
                .args(&["run", "-w", "/home/opam/build", "-v", &format!("{}:/home/opam/build", lib_dir_absolute_path.as_os_str().to_str().unwrap()), "lib_ocaml", "make"])
                .status()
                .expect("Couldn't run build process inside of docker container.");
        }
        _ => unimplemented!("cargo:warning=Invalid OCaml build chain '{}' .", build_chain)
    };
}

fn build_ocaml_libs() {

}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    let ocaml_libs = vec!["tzmock"];
    for lib_name in ocaml_libs.into_iter() {
        let lib_dir = Path::new("lib_ocaml").join(lib_name);
        run_builder(&lib_dir);

        let lib_a = format!("lib{}.a", lib_name);
        let lib_o = format!("lib{}.o", lib_name);
        Command::new("cp")
            .args(&[
                Path::new(&lib_dir).join(&lib_o).to_str().unwrap(),
                Path::new(&out_dir).join(&lib_o).to_str().unwrap(),
            ])
            .status()
            .expect("File copy failed.");
        Command::new("ar")
            .args(&["qs", &lib_a, &lib_o])
            .current_dir(&out_dir)
            .status()
            .expect("ar gave an error");

    }

    println!("cargo:rustc-link-search={}", out_dir);
    println!("cargo:rustc-link-lib=dylib={}", &env::var("OCAML_LIB").unwrap_or("tzmock".to_string()))
}
