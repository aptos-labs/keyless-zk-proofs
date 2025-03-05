// Copyright © Aptos Foundation

use std::{env, path::PathBuf, process::Command};

fn main() {
    println!(
        "{}",
        env::current_dir()
            .expect("Couldn't get working dir.")
            .to_str()
            .expect("couldn't convert pathbuf to str.")
    );

    println!(
        "{:?}",
        Command::new("bash")
            .arg("-c")
            .arg("cd rapidsnark && ./build_lib.sh")
            .output()
            .expect("Failed to build c++ library")
    );

    // Tell cargo to tell rustc to link the system `clang`
    // shared library.
    println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");
    println!("cargo:rerun-if-changed=rapidsnark/src");
    println!("cargo:rerun-if-changed=rapidsnark/meson.build");
    println!("cargo:rerun-if-changed=rapidsnark/build_lib.sh");
    println!("cargo:rerun-if-env-changed=LIBCLANG_STATIC_PATH");
    println!("cargo:rerun-if-env-changed=OPENMP_LIBRARY_PATH");

    println!("cargo:rerun-if-env-changed=LIBCLANG_DYNAMIC_PATH");

    if let Ok(libclang_path) = env::var("LIBCLANG_PATH") {
        println!("cargo:rustc-link-search=native={}", libclang_path);
    }

    // Specify the C++ standard library
    if let Ok(std_cpp_lib_path) = env::var("CXXSTDLIB_PATH") {
        println!("cargo:rustc-link-search=native={}", std_cpp_lib_path);
    }

    let rapidsnark_libdir_path = PathBuf::from("rapidsnark/build")
        .canonicalize()
        .expect("cannot canonicalize libdir path");
    println!(
        "cargo:rustc-link-search={}",
        rapidsnark_libdir_path.to_str().unwrap()
    );

    let onetbb_libdir_path = PathBuf::from("rapidsnark/build/subprojects/oneTBB-2022.0.0")
        .canonicalize()
        .expect("cannot canonicalize libdir path");
    println!(
        "cargo:rustc-link-search={}",
        onetbb_libdir_path.to_str().unwrap()
    );

    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    println!("cargo:rustc-link-lib=static=rapidsnark");

    println!("cargo:rustc-link-lib=dylib=gmp");
    println!("cargo:rustc-link-lib=dylib=tbb");

    os_specific_printlns();

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = build_bindings();

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

#[cfg(not(target_os = "linux"))]
fn os_specific_printlns() {
    let homebrew_libdir_path = PathBuf::from("/opt/homebrew/lib")
        .canonicalize()
        .expect("cannot canonicalize libdir path");
    println!(
        "cargo:rustc-link-search={}",
        homebrew_libdir_path.to_str().unwrap()
    );

    println!("cargo:rustc-link-lib=c++"); // This is needed on macos
}

#[cfg(target_os = "linux")]
fn os_specific_printlns() {
    println!("cargo:rustc-link-lib=stdc++"); // This is needed on linux (will error on macos)
    println!("cargo:rustc-link-search=native=/usr/lib/llvm-14/lib");
    println!("cargo:rustc-link-search=native=./rapidsnark/build");
}

#[cfg(not(target_os = "linux"))]
fn build_bindings() -> bindgen::Bindings {
    let include_path = PathBuf::from("wrapper.hpp")
        // Canonicalize the path as `rustc-link-search` requires an absolute
        // path.
        .canonicalize()
        .expect("cannot canonicalize include path");
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(include_path.to_str().unwrap())
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_arg("-I./rapidsnark/src")
        .clang_arg("-I./rapidsnark/include")
        .clang_arg("-I./rapidsnark/depends/tbb/oneTBB/include")
        .clang_arg("-I./rapidsnark/depends/ffiasm/c")
        .clang_arg("-std=c++17")
        .clang_arg("-stdlib=libc++")
        .blocklist_file("alt_bn128.hpp")
        .blocklist_file("binfile_utils.hpp")
        .blocklist_file("curve.hpp")
        .blocklist_file("exp.hpp")
        .blocklist_file("f2field.hpp")
        .blocklist_file("fft.hpp")
        .blocklist_file("fileloader.hpp")
        .blocklist_file("groth16.hpp")
        .blocklist_file("logger.hpp")
        .blocklist_file("logging.hpp")
        .blocklist_file("misc.hpp")
        .blocklist_file("multiexp.hpp")
        .blocklist_file("naf.hpp")
        .blocklist_file("random_generator.hpp")
        .blocklist_file("scope_guard.hpp")
        .blocklist_file("spinlock.hpp")
        .blocklist_file("splitparstr.hpp")
        .blocklist_file("wtns_utils.hpp")
        .blocklist_file("zkey_utils.hpp")
        .allowlist_file("fullprover.hpp")
        .allowlist_type("FullProver")
        .allowlist_type("ProverResponseType")
        .allowlist_type("ProverError")
        .allowlist_type("ProverResponseMetrics")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    bindings
}

#[cfg(target_os = "linux")]
fn build_bindings() -> bindgen::Bindings {
    let include_path = PathBuf::from("wrapper.hpp")
        // Canonicalize the path as `rustc-link-search` requires an absolute
        // path.
        .canonicalize()
        .expect("cannot canonicalize include path");
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(include_path.to_str().unwrap())
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_arg("-L./rapidsnark/package/lib")
        .clang_arg("-L/usr/lib/llvm-14/lib")
        .clang_arg("-I/usr/lib/llvm-14/lib/clang/14.0.6/include")
        .clang_arg("-I/usr/include/c++/12/")
        .clang_arg("-I/usr/include/x86_64-linux-gnu/c++/12/")
        .clang_arg("-I./rapidsnark/src")
        .clang_arg("-I./rapidsnark/include")
        .clang_arg("-I./rapidsnark/depends/tbb/oneTBB/include")
        .clang_arg("-I./rapidsnark/depends/ffiasm/c")
        .clang_arg("-std=c++17")
        .clang_arg("-stdlib=libc++")
        .blocklist_file("alt_bn128.hpp")
        .blocklist_file("binfile_utils.hpp")
        .blocklist_file("curve.hpp")
        .blocklist_file("exp.hpp")
        .blocklist_file("f2field.hpp")
        .blocklist_file("fft.hpp")
        .blocklist_file("fileloader.hpp")
        .blocklist_file("groth16.hpp")
        .blocklist_file("logger.hpp")
        .blocklist_file("logging.hpp")
        .blocklist_file("misc.hpp")
        .blocklist_file("multiexp.hpp")
        .blocklist_file("naf.hpp")
        .blocklist_file("random_generator.hpp")
        .blocklist_file("scope_guard.hpp")
        .blocklist_file("spinlock.hpp")
        .blocklist_file("splitparstr.hpp")
        .blocklist_file("wtns_utils.hpp")
        .blocklist_file("zkey_utils.hpp")
        .allowlist_file("fullprover.hpp")
        .allowlist_type("FullProver")
        .allowlist_type("ProverResponseType")
        .allowlist_type("ProverError")
        .allowlist_type("ProverResponseMetrics")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    bindings
}
