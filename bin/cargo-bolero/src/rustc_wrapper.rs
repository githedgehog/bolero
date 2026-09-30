//! `cargo-bolero` doubles as a `RUSTC_WRAPPER` for engines that link their fuzzer into the
//! target. The fuzzer's own crates must not be built with the coverage flags, or the fuzzer
//! instruments itself: every edge it takes while mutating and scheduling lands in the
//! coverage map next to the target's, drowning out the signal.
//!
//! They are also built without the sanitizer and without debug assertions. The fuzzer scans
//! the coverage map on every execution, and paying for those checks there cost about 6.5x in
//! throughput while checking nothing about the target. Mixing sanitized and unsanitized
//! crates needs `-Cunsafe-allow-abi-mismatch=sanitizer`, which disables rustc's guard
//! against a half-instrumented build, so it is passed only to the crates at the boundary.

use std::{
    ffi::OsString,
    process::{Command, ExitStatus},
};

/// Bump whenever the wrapper changes the flags it passes. Cargo only fingerprints the
/// wrapper's path, so without this a changed wrapper silently reuses stale artifacts.
pub const VERSION: u32 = 1;

/// Set by `cargo-bolero` on the cargo invocation to select wrapper mode
pub const WRAPPER_ENV: &str = "__BOLERO_RUSTC_WRAPPER";
/// The `RUSTC_WRAPPER` the user already had, if any, which we chain to
pub const INNER_WRAPPER_ENV: &str = "__BOLERO_INNER_RUSTC_WRAPPER";

/// Crates that make up the in-process fuzzer, including the dependencies on its per-execution
/// hot path (hashing, and SIMD scanning of the coverage map). `bolero_libafl` is here because
/// the fuzzer's generic code is compiled in the crate that instantiates it.
const UNINSTRUMENTED_CRATES: &[&str] = &[
    "bolero_libafl",
    "libafl",
    "libafl_bolts",
    "libafl_core",
    "libafl_derive",
    "libafl_targets",
    "safe_arch",
    "wide",
    "xxhash_rust",
];

/// Crates that link sanitized code against the unsanitized fuzzer
const SANITIZER_BOUNDARY_CRATES: &[&str] = &["bolero", "bolero_libafl"];

pub fn is_wrapper_invocation() -> bool {
    std::env::var_os(WRAPPER_ENV).is_some()
}

/// Run as `$RUSTC_WRAPPER $RUSTC <args>`, as cargo invokes it
pub fn run() -> ! {
    let mut args = std::env::args_os().skip(1);
    let rustc = args
        .next()
        .expect("cargo passes the rustc path to the wrapper");
    let args: Vec<OsString> = args.collect();

    let crate_name = args
        .iter()
        .position(|arg| arg == "--crate-name")
        .and_then(|i| args.get(i + 1))
        .and_then(|name| name.to_str())
        .map(str::to_owned);

    let name = crate_name.as_deref().unwrap_or_default();
    let mut args = args;
    if UNINSTRUMENTED_CRATES.contains(&name) {
        args = strip_sanitizer_flags(strip_coverage_flags(args));
        // the fuzzer runs its bookkeeping on every execution; checked profiles would slow
        // it down without checking anything about the target
        args.push("-Cdebug-assertions=off".into());
        args.push("-Coverflow-checks=off".into());
    }
    if SANITIZER_BOUNDARY_CRATES.contains(&name) {
        args.push("-Cunsafe-allow-abi-mismatch=sanitizer".into());
    }

    let mut cmd = match std::env::var_os(INNER_WRAPPER_ENV).filter(|w| !w.is_empty()) {
        Some(inner) => {
            let mut cmd = Command::new(inner);
            cmd.arg(rustc);
            cmd
        }
        None => Command::new(rustc),
    };
    cmd.args(args);

    let status = cmd.status().expect("could not run rustc");
    std::process::exit(exit_code(status));
}

fn strip_coverage_flags(args: Vec<OsString>) -> Vec<OsString> {
    fn is_coverage(value: &str) -> bool {
        value.starts_with("llvm-args=-sanitizer-coverage") || value.starts_with("passes=sancov")
    }

    let mut out = Vec::with_capacity(args.len());
    let mut args = args.into_iter().peekable();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            // `-C value`, split across two arguments
            Some("-C") => {
                if args
                    .peek()
                    .and_then(|value| value.to_str())
                    .is_some_and(is_coverage)
                {
                    args.next();
                } else {
                    out.push(arg);
                }
            }
            Some(flag) if flag.strip_prefix("-C").is_some_and(is_coverage) => {}
            _ => out.push(arg),
        }
    }
    out
}

/// The fuzzer's own bookkeeping (scanning and classifying the coverage map on every
/// execution) does not need to be checked by a sanitizer, and paying for the checks there
/// costs a large share of the throughput
fn strip_sanitizer_flags(args: Vec<OsString>) -> Vec<OsString> {
    let mut out = Vec::with_capacity(args.len());
    let mut args = args.into_iter().peekable();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-Z") => {
                if args
                    .peek()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.starts_with("sanitizer"))
                {
                    args.next();
                } else {
                    out.push(arg);
                }
            }
            Some(flag) if flag.starts_with("-Zsanitizer") => {}
            _ => out.push(arg),
        }
    }
    out
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(101)
}
