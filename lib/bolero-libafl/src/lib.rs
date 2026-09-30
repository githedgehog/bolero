//! LibAFL plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.
//!
//! The fuzzer runs in-process: edge coverage comes from the `trace-pc-guard` callbacks and
//! comparison operands from the `trace-cmp` callbacks, both provided by `libafl_targets`, so
//! the target must be built with the matching `-sanitizer-coverage-*` flags (which
//! `cargo-bolero` passes). The comparison log feeds an input-to-state stage, which is what
//! lets the fuzzer solve multi-byte magic values.
//!
//! `cargo-bolero` configures the run through `BOLERO_LIBAFL_*` environment variables.

#[doc(hidden)]
#[cfg(all(feature = "lib", fuzzing_libafl))]
pub mod fuzzer {
    use bolero_engine::{
        driver, input, panic, Engine, Failure, Never, ScopedEngine, TargetLocation, Test,
    };
    use core::time::Duration;
    use libafl::{
        corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
        events::SimpleEventManager,
        executors::{inprocess::InProcessExecutor, ExitKind, ShadowExecutor},
        feedback_or_fast,
        feedbacks::{CrashFeedback, MaxMapFeedback, TimeoutFeedback},
        fuzzer::{Evaluator, Fuzzer, StdFuzzer},
        inputs::{BytesInput, HasTargetBytes, Input},
        monitors::SimpleMonitor,
        mutators::{havoc_mutations, token_mutations::I2SRandReplace, HavocScheduledMutator},
        observers::{CanTrack, TimeObserver},
        schedulers::{
            powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
        },
        stages::{
            calibrate::CalibrationStage, power::StdPowerMutationalStage, ShadowTracingStage,
            StdMutationalStage, SyncFromDiskStage,
        },
        state::{HasCorpus, HasExecutions, HasMaxSize, HasSolutions, StdState},
    };
    use libafl_bolts::{rands::StdRand, tuples::tuple_list};
    use libafl_targets::{std_edges_map_observer, CmpLogObserver};
    use std::{
        path::{Path, PathBuf},
        time::Instant,
    };

    /// How often a worker imports the corpus entries other workers found
    const SYNC_INTERVAL: Duration = Duration::from_secs(2);

    #[derive(Debug, Default)]
    pub struct LibAflEngine {}

    impl LibAflEngine {
        pub fn new(_location: TargetLocation) -> Self {
            Self::default()
        }
    }

    impl<T: Test> Engine<T> for LibAflEngine
    where
        T::Value: core::fmt::Debug,
    {
        type Output = Never;

        fn run(self, mut test: T, options: driver::Options) -> Self::Output {
            panic::set_hook();
            panic::forward_panic(false);

            let mut ctx = bolero_engine::TestRunContext::new(
                bolero_engine::EngineKind::LibAfl,
                bolero_engine::TestInput::default(),
                0,
                bolero_engine::RunPhase::Normal,
            );
            ctx.shrink_enabled = !options.shrink_time_or_default().is_zero();
            let _ctx_guard = bolero_engine::test_context::enter(ctx);

            let mut iteration = 0u64;
            let crash = fuzz(&mut |slice: &[u8]| {
                start_iteration(&mut iteration);
                let mut input = input::Bytes::new(slice, &options);
                test.test(&mut input).is_err()
            });

            let Some(slice) = crash else {
                std::process::exit(0);
            };
            claim_report();

            report("test failed; shrinking input...".into());
            if let Some(shrunken) = test.shrink(slice.clone(), None, &options) {
                // shrink.rs already ran the final confirmed-failure execution
                // with RunPhase::Failure set
                report(format!("{shrunken:#}"));
            } else {
                bolero_engine::test_context::update(|ctx| {
                    ctx.run_phase = bolero_engine::RunPhase::Failure;
                });
                let mut replay = input::Bytes::new(&slice, &options);
                let error = match test.test(&mut replay) {
                    Err(error) => error,
                    Ok(_) => {
                        report(
                            "the failing input did not fail again; the test may be flaky".into(),
                        );
                        std::process::exit(1);
                    }
                };
                let input = input::Bytes::new(&slice, &options);
                report(format!(
                    "{:#}",
                    Failure {
                        seed: None,
                        error,
                        input
                    }
                ));
            }

            bolero_engine::test_context::invoke_on_failure();
            std::process::exit(1);
        }
    }

    impl ScopedEngine for LibAflEngine {
        type Output = Never;

        fn run<F, R>(self, mut test: F, options: driver::Options) -> Self::Output
        where
            F: FnMut() -> R + core::panic::RefUnwindSafe,
            R: bolero_engine::IntoResult,
        {
            panic::set_hook();
            panic::forward_panic(false);

            let mut ctx = bolero_engine::TestRunContext::new(
                bolero_engine::EngineKind::LibAfl,
                bolero_engine::TestInput::default(),
                0,
                bolero_engine::RunPhase::Normal,
            );
            // The scoped path does not shrink, like the other engines
            ctx.shrink_enabled = false;
            let _ctx_guard = bolero_engine::test_context::enter(ctx);

            let options = &options;
            let driver = bolero_engine::driver::bytes::Driver::new(&[][..], options);
            let driver = bolero_engine::driver::object::Object(driver);
            let mut driver = Some(Box::new(driver));

            let mut iteration = 0u64;
            let mut run = |slice: &[u8]| {
                // extend the lifetime of the slice so it can be stored in TLS
                let input: &'static [u8] = unsafe { core::mem::transmute::<&[u8], &[u8]>(slice) };
                let mut drv = driver.take().unwrap();
                drv.reset(input, options);
                let (drv, result) = bolero_engine::any::run(drv, &mut test);
                driver = Some(drv);
                result
            };

            let crash = fuzz(&mut |slice: &[u8]| {
                start_iteration(&mut iteration);
                run(slice).is_err()
            });

            let Some(slice) = crash else {
                std::process::exit(0);
            };
            claim_report();

            bolero_engine::test_context::update(|ctx| {
                ctx.run_phase = bolero_engine::RunPhase::Failure;
            });
            if let Err(error) = run(&slice) {
                report(format!(
                    "{:#}",
                    Failure {
                        seed: None,
                        error,
                        input: (),
                    }
                ));
            }

            bolero_engine::test_context::invoke_on_failure();
            std::process::exit(1);
        }
    }

    /// The engine's own failures, as opposed to the test's. bolero's panic hook captures
    /// panics silently (it reports them as test failures), so a panic here would exit the
    /// worker without a word; report the error and exit with a code no test failure uses.
    trait OrFatal<T> {
        fn or_fatal(self, what: &str) -> T;
    }

    impl<T, E: core::fmt::Display> OrFatal<T> for Result<T, E> {
        fn or_fatal(self, what: &str) -> T {
            match self {
                Ok(value) => value,
                Err(error) => {
                    report(format!("libafl engine error: {what}: {error}"));
                    std::process::exit(FATAL_EXIT_CODE);
                }
            }
        }
    }

    impl<T> OrFatal<T> for Option<T> {
        fn or_fatal(self, what: &str) -> T {
            match self {
                Some(value) => value,
                None => {
                    report(format!("libafl engine error: {what}"));
                    std::process::exit(FATAL_EXIT_CODE);
                }
            }
        }
    }

    const FATAL_EXIT_CODE: i32 = 3;

    /// Write `message` to stderr in one call. Stderr is unbuffered and several workers share
    /// it, so a message written in fragments interleaves with theirs.
    fn report(message: String) {
        use std::io::Write;
        let _ = std::io::stderr().write_all(format!("{message}\n").as_bytes());
    }

    /// With several workers, the first to fail shrinks and reports. The others have already
    /// saved their failing input to the crashes dir, and park until `cargo-bolero` stops them:
    /// exiting would read as the failure and get the reporting worker killed mid-shrink.
    fn claim_report() {
        let Some(lock) = std::env::var_os("BOLERO_LIBAFL_REPORT_LOCK") else {
            return;
        };
        let claimed = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
            .is_ok();
        if !claimed {
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
    }

    /// Clear any `on_failure` callback from the previous iteration, then reset the
    /// per-iteration context fields before running the next input.
    fn start_iteration(iteration: &mut u64) {
        bolero_engine::test_context::clear_on_failure();
        bolero_engine::test_context::update(|ctx| {
            ctx.iteration = *iteration;
            ctx.run_phase = bolero_engine::RunPhase::Normal;
        });
        *iteration += 1;
    }

    struct Config {
        corpus_dir: PathBuf,
        crashes_dir: PathBuf,
        time: Option<Duration>,
        runs: Option<u64>,
        timeout: Duration,
        seed: Option<u64>,
        max_len: Option<usize>,
        /// This process's index among the workers `cargo-bolero` started for `--jobs`
        worker: u64,
    }

    impl Config {
        fn from_env() -> Self {
            fn var<T: core::str::FromStr>(name: &str) -> Option<T> {
                let value = std::env::var(name).ok()?;
                let parsed = value.parse().ok();
                Some(parsed.or_fatal(&format!("invalid {name}={value:?}")))
            }

            Self {
                corpus_dir: var("BOLERO_LIBAFL_CORPUS_DIR")
                    .or_fatal("missing BOLERO_LIBAFL_CORPUS_DIR"),
                crashes_dir: var("BOLERO_LIBAFL_CRASHES_DIR")
                    .or_fatal("missing BOLERO_LIBAFL_CRASHES_DIR"),
                time: var("BOLERO_LIBAFL_TIME_SECS").map(Duration::from_secs),
                runs: var("BOLERO_LIBAFL_RUNS"),
                timeout: var("BOLERO_LIBAFL_TIMEOUT_SECS")
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(10)),
                seed: var("BOLERO_LIBAFL_SEED"),
                max_len: var("BOLERO_LIBAFL_MAX_LEN"),
                worker: var("BOLERO_LIBAFL_WORKER").unwrap_or(0),
            }
        }
    }

    /// The `libafl_targets` edge map, which the coverage callbacks write
    struct EdgesMap {
        ptr: *mut u8,
        len: usize,
    }

    impl EdgesMap {
        fn new() -> Self {
            Self {
                ptr: libafl_targets::edges_map_mut_ptr(),
                len: libafl_targets::edges_max_num(),
            }
        }

        /// AFL-style hit count buckets, applied only to the non-zero words of the map
        fn classify_counts(&self) {
            // Safety: the map outlives the fuzzer and nothing else touches it between the
            // target returning and the observers reading it
            let map = unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) };
            let (head, words, tail) = unsafe { map.align_to_mut::<u64>() };
            head.iter_mut().for_each(classify);
            tail.iter_mut().for_each(classify);
            for word in words {
                if *word != 0 {
                    let mut bytes = word.to_ne_bytes();
                    bytes.iter_mut().for_each(classify);
                    *word = u64::from_ne_bytes(bytes);
                }
            }
        }
    }

    #[inline]
    fn classify(count: &mut u8) {
        *count = match *count {
            0..=3 => [0, 1, 2, 4][*count as usize],
            4..=7 => 8,
            8..=15 => 16,
            16..=31 => 32,
            32..=127 => 64,
            128..=255 => 128,
        };
    }

    /// Fuzz `test` until it fails or the configured budget runs out.
    ///
    /// `test` returns `true` when an input fails. Returns the first failing input, if any.
    fn fuzz(test: &mut dyn FnMut(&[u8]) -> bool) -> Option<Vec<u8>> {
        let config = Config::from_env();

        // with several workers, only the first reports progress
        let quiet = config.worker != 0;
        let monitor = SimpleMonitor::new(move |s| {
            if !quiet {
                eprintln!("{s}");
            }
        });
        let mut mgr = SimpleEventManager::new(monitor);

        // The map has an entry for every instrumented edge in the test binary (hundreds of
        // thousands for a large crate), of which one execution touches a few hundred.
        // `HitcountsMapObserver` classifies every entry of the map on every execution, so the
        // harness classifies the map itself, skipping the zero words, instead.
        let edges = EdgesMap::new();
        let edges_observer = unsafe { std_edges_map_observer("edges") }.track_indices();
        let time_observer = TimeObserver::new("time");
        let cmplog_observer = CmpLogObserver::new("cmplog", true);

        let map_feedback = MaxMapFeedback::new(&edges_observer);
        let calibration = CalibrationStage::new(&map_feedback);
        let mut feedback = map_feedback;
        // libfuzzer and honggfuzz both report a timeout as a failure
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        let rand = match config.seed {
            Some(seed) => StdRand::with_seed(seed.wrapping_add(config.worker)),
            None => StdRand::new(),
        };

        let mut state = StdState::new(
            rand,
            // Workers share these dirs. A per-worker file name prefix means two workers never
            // write the same file (which they would for equal inputs, since entries are named
            // by content hash), so no lock files are needed either. No metadata files: the
            // other workers import every file in the corpus dir as an input.
            InMemoryOnDiskCorpus::with_meta_format_and_prefix(
                &config.corpus_dir,
                None,
                Some(format!("w{}-", config.worker)),
                false,
            )
            .or_fatal("could not open the corpus"),
            OnDiskCorpus::with_meta_format_and_prefix(
                &config.crashes_dir,
                None,
                Some(format!("w{}-", config.worker)),
                false,
            )
            .or_fatal("could not open the crashes dir"),
            &mut feedback,
            &mut objective,
        )
        .or_fatal("could not create the fuzzer state");

        if let Some(max_len) = config.max_len {
            state.set_max_size(max_len);
        }

        let scheduler = IndexesLenTimeMinimizerScheduler::new(
            &edges_observer,
            StdWeightedScheduler::with_schedule(
                &mut state,
                &edges_observer,
                Some(PowerSchedule::fast()),
            ),
        );
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut failing: Option<Vec<u8>> = None;
        let mut harness = |input: &BytesInput| {
            let bytes = input.target_bytes();
            let slice: &[u8] = &bytes;
            let failed = test(slice);
            edges.classify_counts();
            if failed {
                failing.get_or_insert_with(|| slice.to_vec());
                ExitKind::Crash
            } else {
                ExitKind::Ok
            }
        };

        // The executor installs a panic hook that records the input and exits the process.
        // bolero already turns a panic into a test failure (which the harness reports as a
        // crash), and must keep the process alive to shrink and report it, so put bolero's
        // hook back. LibAFL's signal handlers still catch real crashes and timeouts.
        let bolero_hook = std::panic::take_hook();
        let executor = InProcessExecutor::builder()
            .timeout(config.timeout)
            .harness(&mut harness)
            .observers(tuple_list!(edges_observer, time_observer))
            .fuzzer(&mut fuzzer)
            .state(&mut state)
            .event_mgr(&mut mgr)
            .build()
            .or_fatal("could not create the executor");
        drop(std::panic::take_hook());
        std::panic::set_hook(bolero_hook);
        let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

        let tracing = ShadowTracingStage::new();
        let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
            I2SRandReplace::new()
        )));
        let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
            StdPowerMutationalStage::new(HavocScheduledMutator::new(havoc_mutations()));
        // Workers share the corpus dir: each writes its finds there and periodically imports
        // the others'. Hidden files are not corpus entries.
        let sync = SyncFromDiskStage::new(
            vec![config.corpus_dir.clone()],
            |_fuzzer: &mut _, _state: &mut _, path: &Path| {
                let hidden = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with('.'));
                if hidden {
                    return Err(libafl::Error::invalid_input("not a corpus entry"));
                }
                BytesInput::from_file(path)
            },
            SYNC_INTERVAL,
            "sync",
        );
        let mut stages = tuple_list!(calibration, tracing, i2s, power, sync);

        if state.must_load_initial_inputs() {
            let has_seeds = std::fs::read_dir(&config.corpus_dir)
                .map(|mut dir| dir.next().is_some())
                .unwrap_or(false);
            if has_seeds {
                state
                    .load_initial_inputs_forced(
                        &mut fuzzer,
                        &mut executor,
                        &mut mgr,
                        core::slice::from_ref(&config.corpus_dir),
                    )
                    .or_fatal("could not load the corpus");
            }
        }
        if state.corpus().count() == 0 {
            fuzzer
                .add_input(&mut state, &mut executor, &mut mgr, BytesInput::new(vec![]))
                .or_fatal("could not add the initial input");
        }

        let start = Instant::now();
        while state.solutions().count() == 0 {
            if config.time.is_some_and(|time| start.elapsed() >= time) {
                break;
            }
            if config.runs.is_some_and(|runs| *state.executions() >= runs) {
                break;
            }
            fuzzer
                .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
                .or_fatal("fuzzing failed");
        }

        report(format!(
            "libafl[{}]: {} executions in {:?}, corpus {}, crashes {}",
            config.worker,
            state.executions(),
            start.elapsed(),
            state.corpus().count(),
            state.solutions().count(),
        ));

        drop(executor);
        if failing.is_none() && state.solutions().count() > 0 {
            // a timeout or a signal (e.g. a sanitizer abort) never returns to the harness
            report(format!(
                "libafl: found a crash or timeout; the input is saved in {}",
                config.crashes_dir.display()
            ));
            std::process::exit(1);
        }
        failing
    }
}

#[doc(hidden)]
#[cfg(all(feature = "lib", fuzzing_libafl))]
pub use fuzzer::*;
