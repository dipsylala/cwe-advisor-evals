## Verdict

Confirmed. The loop bound is off by one: it iterates `n + 1` times instead of `n` times, writing one element past the end of `out` (and reading one element past the intended window of `history`).

## Source

`copy_recent_events` in `RecentEventsOffByOneCopy.c`. `n` is correctly clamped to `min(history_len, max_out)`, so `out` is only guaranteed to hold `max_out` elements and `n <= max_out`. The loop condition `i <= n` runs for `i = 0 .. n` inclusive, which is `n + 1` iterations. When `n == max_out` (the caller-supplied output buffer is the limiting factor, the common case), the final iteration writes `out[n]`, i.e. `out[max_out]`, one element beyond the end of the caller's buffer. The same iteration also reads `history[start + n]`, which is `history[history_len]`, one element past the end of the source array.

## Fix

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

The bound `n` already accounts for both the size of `history` (via `history_len`) and the size of `out` (via `max_out`): it is the number of elements that safely fit in both. A loop that copies `n` elements into `out` and reads `n` elements starting at `start` from `history` must run exactly `n` times, for indices `0` through `n - 1`. Using `<=` instead of `<` performs one extra iteration that writes `out[n]`, which is out of bounds whenever `out` was sized to exactly `max_out` elements (the scenario `max_out` exists to guard against), and reads `history[history_len]`, which is out of bounds whenever `history` was sized to exactly `history_len` elements. Changing the comparison to `i < n` makes the loop iterate exactly `n` times, matching the buffer sizes actually guaranteed by the function's contract, with no change to the function's behavior for any previously in-bounds case: it still returns `n` and copies the same `n` most-recent entries.
