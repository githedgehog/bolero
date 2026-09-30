#include "../afl/types.h"

static u64 parsed_afl_max_cycles = 0;

static u64 bolero_afl_max_cycles() {
    if (!parsed_afl_max_cycles) {
        u8* max_cycles = getenv("BOLERO_AFL_MAX_CYCLES");

        if (max_cycles < 1 || sscanf(max_cycles, "%llu", &parsed_afl_max_cycles) < 1) {
            // set a default
            parsed_afl_max_cycles = 100;
        }
    }

    return parsed_afl_max_cycles;
}

static u8  parsed_afl_run_time = 0;
static u64 afl_run_time_ms = 0;

// Wall-clock budget in milliseconds from BOLERO_AFL_RUN_TIME (seconds); 0 means unlimited.
static u64 bolero_afl_run_time_ms() {
    if (!parsed_afl_run_time) {
        parsed_afl_run_time = 1;
        u8* run_time = getenv("BOLERO_AFL_RUN_TIME");
        u64 secs = 0;

        if (run_time && sscanf(run_time, "%llu", &secs) == 1) {
            afl_run_time_ms = secs * 1000;
        }
    }

    return afl_run_time_ms;
}
