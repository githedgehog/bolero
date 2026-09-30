use crate::{exec, reduce, test, Selection};
use anyhow::{Context, Result};
use std::{
    fs,
    process::{Command, ExitStatus},
    time::Duration,
};

const FLAGS: &[&str] = &[
    "--cfg fuzzing_libafl",
    "-Cllvm-args=-sanitizer-coverage-level=3",
    "-Cllvm-args=-sanitizer-coverage-trace-pc-guard",
    "-Cllvm-args=-sanitizer-coverage-prune-blocks=0",
    // feeds the comparison log that drives the input-to-state stage
    "-Cllvm-args=-sanitizer-coverage-trace-compares",
];

pub(crate) fn test(selection: &Selection, test_args: &test::Args) -> Result<()> {
    let test_target = selection.test_target(FLAGS, "libafl")?;
    let corpus_dir = test_args
        .corpus_dir
        .clone()
        .unwrap_or_else(|| test_target.default_corpus_dir());
    let crashes_dir = test_args
        .crashes_dir
        .clone()
        .unwrap_or_else(|| test_target.default_crashes_dir());

    fs::create_dir_all(&corpus_dir)?;
    fs::create_dir_all(&crashes_dir)?;

    let mut cmd = test_target.command();
    cmd.env("BOLERO_LIBAFL_CORPUS_DIR", &corpus_dir)
        .env("BOLERO_LIBAFL_CRASHES_DIR", &crashes_dir)
        .env(
            "BOLERO_LIBAFL_TIMEOUT_SECS",
            test_args.timeout_as_secs().to_string(),
        );

    if let Some(time) = test_args.time_as_secs() {
        cmd.env("BOLERO_LIBAFL_TIME_SECS", time.to_string());
    }
    if let Some(runs) = test_args.runs {
        cmd.env("BOLERO_LIBAFL_RUNS", runs.to_string());
    }
    if let Some(seed) = test_args.seed {
        cmd.env("BOLERO_LIBAFL_SEED", seed.to_string());
    }
    if let Some(max_len) = test_args.max_input_length {
        cmd.env("BOLERO_LIBAFL_MAX_LEN", max_len.to_string());
    }
    if !test_args.engine_args.is_empty() {
        eprintln!("warning: the libafl engine takes no engine arguments; ignoring them");
    }

    let workers = test_args.jobs.unwrap_or(1).max(1);
    if workers == 1 {
        return exec(cmd);
    }
    run_workers(cmd, workers)
}

/// Run `workers` copies of the fuzzer, which share the corpus dir, until one of them fails or
/// they all finish.
///
/// Independent processes rather than LibAFL's broker: bolero stops at the first failure to
/// shrink and report it, which is simplest when a failure is just a process exiting non-zero,
/// and there is no broker port to collide with another fuzzing job on the same host.
fn run_workers(mut cmd: Command, workers: usize) -> Result<()> {
    // the first worker to fail claims this to report; the rest stop quietly
    let report_lock = tempfile::Builder::new()
        .prefix("bolero-libafl-report")
        .tempdir()?;
    cmd.env(
        "BOLERO_LIBAFL_REPORT_LOCK",
        report_lock.path().join("claimed"),
    );

    let mut children = Vec::with_capacity(workers);
    for worker in 0..workers {
        cmd.env("BOLERO_LIBAFL_WORKER", worker.to_string());
        let child = cmd
            .spawn()
            .with_context(|| format!("spawning worker {worker}: {cmd:?}"))?;
        children.push(Some(child));
    }

    let mut failure: Option<(usize, ExitStatus)> = None;
    while failure.is_none() && children.iter().any(Option::is_some) {
        for (worker, slot) in children.iter_mut().enumerate() {
            let Some(child) = slot else { continue };
            if let Some(status) = child.try_wait()? {
                *slot = None;
                if !status.success() {
                    failure = Some((worker, status));
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // stop the rest, whether one failed or we are unwinding
    for child in children.iter_mut().flatten() {
        let _ = child.kill();
        let _ = child.wait();
    }

    match failure {
        None => Ok(()),
        Some((_worker, status)) => Err(anyhow::anyhow!("libafl found a failure: {status}")),
    }
}

pub(crate) fn reduce(_selection: &Selection, _reduce: &reduce::Args) -> Result<()> {
    anyhow::bail!("the libafl engine does not support reduce yet")
}
