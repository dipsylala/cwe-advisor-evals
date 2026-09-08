## Verdict

exploitable

## Source

`max_out` and `history_len`, the caller-supplied bounds passed into `copy_recent_events`. `n` is computed as `min(history_len, max_out)`, so `n <= max_out` holds by construction.

## Fix

The loop bound is the defect: `for (size_t i = 0; i <= n; i++)` runs for `i = 0 .. n` inclusive, i.e. `n + 1` iterations, one more than either `history` (valid source offsets `start .. start + n - 1`) or `out` (valid indices `0 .. max_out - 1`, and `n <= max_out`) can support. The final iteration writes `out[n]`, one `Event` past the end of the caller's `out` buffer whenever `n == max_out` (the common case, since `copy_recent_events` exists to fill an out array up to its capacity), and reads `history[start + n] == history[history_len]`, one element past the end of `history`, on every call. Valid indices for a loop copying `n` elements are `0` to `n - 1`; the condition must be `i < n`.

### File: RecentEventsOffByOneCopy.c
```c
#include <stddef.h>

typedef struct {
    unsigned id;
    unsigned code;
} Event;

/* Copies at most max_out of the most recent entries from history into out.
 * Returns the number of entries copied. */
size_t copy_recent_events(const Event *history, size_t history_len, Event *out, size_t max_out)
{
    size_t n = history_len < max_out ? history_len : max_out;
    size_t start = history_len - n;

    for (size_t i = 0; i < n; i++) {
        out[i] = history[start + i];
    }

    return n;
}
```

## Explanation

The only change is the loop condition, `i <= n` to `i < n`. `n` is already the exact number of entries that both fit in `out` (`n <= max_out`) and exist in `history` starting at `start` (`start + n == history_len`), so the loop needs exactly `n` iterations over indices `0 .. n - 1`. The off-by-one `<=` produced an extra iteration at `i == n`, writing `out[n]` (out of bounds whenever the caller sized `out` to exactly `max_out` and `n == max_out`) from `history[history_len]` (always out of bounds, since valid `history` indices run `0 .. history_len - 1`). Correcting the bound removes both the out-of-bounds write and the matching out-of-bounds read without altering what the function returns or how many entries it copies when called correctly.

## Behaviour changes

none - the function still copies `n = min(history_len, max_out)` entries starting at `start = history_len - n` and returns `n`; the fix only removes the extra, out-of-bounds iteration that the loop was never intended to perform.

**Verification**: no C compiler (gcc/clang/cl) was reachable in this environment to compile the fixed file. Manual check: the change is a single relational-operator edit (`<=` to `<`) with no new symbols, calls, includes, or signature changes introduced; `sizeof`/type usage is unchanged; the revised bound was hand-traced against both buffers as described above and matches the standard `0 <= i < n` loop idiom used elsewhere in the codebase's C entries.

**Assumptions**: none - the vulnerable pattern (loop bound `i <= n` where `i < n` is intended) is unambiguous and directly matches the C-specific guidance ("Valid indices are `0` to `size - 1`: a loop written `i <= size` writes one element past the end of every buffer it touches").
