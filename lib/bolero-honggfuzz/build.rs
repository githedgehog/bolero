use std::{env, path::PathBuf, process::Command};

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
const MAKE_COMMAND: &str = "make";
#[cfg(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
))]
const MAKE_COMMAND: &str = "gmake";

/// Builds `target` (a path relative to the honggfuzz tree, e.g. `libhfuzz/libhfuzz.a`) along with
/// `libhfcommon`, and links both as `lib` and `hfcommon`.
///
/// The build happens out-of-tree in `OUT_DIR`, so the (possibly read-only) crate sources are never
/// written to and concurrent builds of this crate don't race on the same object files.
fn build(target: &str, lib: &str) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target = out_dir.join(target);
    let hfcommon = out_dir.join("libhfcommon/libhfcommon.a");

    let status = Command::new(MAKE_COMMAND)
        .arg("-C")
        .arg("honggfuzz")
        .arg(format!("BUILD_DIR={}", out_dir.display()))
        .arg(&target)
        .arg(&hfcommon)
        .status()
        .unwrap();
    assert!(status.success());

    for (archive, lib) in [(&target, lib), (&hfcommon, "hfcommon")] {
        let dir = archive.parent().unwrap();
        println!("cargo:rustc-link-search=native={}", dir.display());
        println!("cargo:rustc-link-lib=static={lib}");
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=BOLERO_FUZZER");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_FUZZING_HONGGFUZZ");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_BIN");
    println!("cargo:rerun-if-changed=honggfuzz");

    if std::env::var("CARGO_CFG_FUZZING_HONGGFUZZ").is_ok() {
        build("libhfuzz/libhfuzz.a", "hfuzz");
        return;
    }

    if std::env::var("CARGO_FEATURE_BIN").is_ok() {
        build("libhonggfuzz.a", "honggfuzz");

        if cfg!(target_os = "macos") {
            println!("cargo:rustc-link-search=framework=/System/Library/PrivateFrameworks");
            println!("cargo:rustc-link-search=framework=/System/Library/Frameworks");

            for framework in [
                "CoreSymbolication",
                "IOKit",
                "Foundation",
                "ApplicationServices",
                "Symbolication",
                "CoreServices",
                "CrashReporterSupport",
                "CoreFoundation",
                "CommerceKit",
            ]
            .iter()
            {
                println!("cargo:rustc-link-lib=framework={framework}");
            }
        }

        if cfg!(target_os = "linux") {
            for lib in [
                "unwind-ptrace",
                "unwind-generic",
                "unwind",
                "opcodes",
                "bfd",
            ]
            .iter()
            {
                println!("cargo:rustc-link-lib={lib}");
            }
        }
    }
}
