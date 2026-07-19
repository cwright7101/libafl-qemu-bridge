/*
 * halucinator-native edge-coverage QMP commands.
 *
 * libafl-qemu's coverage TCG instrumentation is compiled into the standalone
 * qemu-system binary, but nothing registers a coverage hook unless the embedded
 * LibAFL Rust harness does. These commands register one from C so an external
 * GDB+QMP driver (HALucinator's LibAflQemuBackend) can drive coverage-guided
 * fuzzing on the QEMU backend -- alongside syx-snapshot.
 *
 * We use a *block* hook (libafl/hooks/tcg/block.c) with a C exec callback, and
 * accumulate AFL-style edge coverage in the callback itself:
 *
 *   - The block pre-gen hook fires from the translator (translate-all.c) for
 *     every translated block; we hash the block PC to a location id.
 *   - The block exec callback fires on every block *execution* and folds the
 *     classic AFL edge id (prev_loc ^ cur_loc) into our own hitcount map.
 *
 * A block hook (vs. an edge hook) records regardless of TB chaining, which GDB
 * single-step / breakpoints / icount all suppress -- so the edge hook records
 * nothing under external debug control. Doing the map update in the C exec
 * callback (rather than the emitted-TCG jit writer) keeps it independent of the
 * in-binary __afl_area_ptr_local / __afl_map_size plumbing and TCG-emission
 * details: a helper call per block is marginally slower than inlined jit
 * coverage but correct and robust for GDB+QMP-driven fuzzing.
 *
 * To keep QMP responses tiny (no shipping the 64 KB map every fuzz iteration),
 * the map diff/fold is done here in C and only counts are returned:
 *   libafl-cov-open    -- register the block hook, zero the coverage + cumulative
 *                         maps and prev_loc (idempotent enable + reset).
 *   libafl-cov-result  -- fold this run's edges into the cumulative seen-set,
 *                         zero the current map for the next run, and return the
 *                         number of NEW edges this run hit plus the running total.
 *
 * The maps are host-side (not guest RAM / vmstate), so a syx-snapshot restore
 * does not touch them -- the fuzzer resets coverage itself via these commands.
 *
 * No avatar2 dependency.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-avatar-target.h"
#include "libafl/hooks/tcg/block.h"     /* libafl_add_block_hook */

#define HAL_COV_SIZE 65536              /* AFL MAP_SIZE (1 << 16) */
#define HAL_COV_MASK (HAL_COV_SIZE - 1)

static uint8_t hal_cov_current[HAL_COV_SIZE];      /* edges hit this run */
static uint8_t hal_cov_cumulative[HAL_COV_SIZE];   /* edges seen across all runs */
static uint64_t hal_cov_prev;                      /* rolling prev location */
static bool hal_cov_registered;

/* Per-block location id: hash the block PC across the map. Returned at
 * translation time and handed back to the exec callback for each execution. */
static uint64_t hal_cov_block_gen(uint64_t data, target_ulong pc)
{
    uint64_t h = (uint64_t)pc * 0x9E3779B1ULL;
    h ^= h >> 15;
    return h & HAL_COV_MASK;
}

/* Runs on every block execution: fold the AFL edge id (prev ^ cur) into the
 * current hitcount map, then shift prev (the classic AFL scheme). */
static void hal_cov_block_exec(uint64_t data, uint64_t id)
{
    uint64_t idx = (hal_cov_prev ^ id) & HAL_COV_MASK;
    if (hal_cov_current[idx] != 0xff) {
        hal_cov_current[idx]++;
    }
    hal_cov_prev = id >> 1;
}

void qmp_libafl_cov_open(Error **errp)
{
    if (!hal_cov_registered) {
        /* Registering the hook also tb_flush()es every CPU, so already-
         * translated blocks re-translate WITH the coverage instrumentation. */
        libafl_add_block_hook(hal_cov_block_gen, NULL, hal_cov_block_exec, 0);
        hal_cov_registered = true;
    }
    memset(hal_cov_current, 0, HAL_COV_SIZE);
    memset(hal_cov_cumulative, 0, HAL_COV_SIZE);
    hal_cov_prev = 0;
}

CovResult *qmp_libafl_cov_result(Error **errp)
{
    CovResult *r = g_new0(CovResult, 1);
    int64_t new_edges = 0, total = 0;
    int i;

    for (i = 0; i < HAL_COV_SIZE; i++) {
        if (hal_cov_current[i] && !hal_cov_cumulative[i]) {
            new_edges++;
            hal_cov_cumulative[i] = hal_cov_current[i];
        }
        if (hal_cov_cumulative[i]) {
            total++;
        }
    }
    /* Ready the current map for the next run. */
    memset(hal_cov_current, 0, HAL_COV_SIZE);
    hal_cov_prev = 0;
    r->new_edges = new_edges;
    r->total_edges = total;
    return r;
}
