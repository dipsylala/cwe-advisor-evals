## Verdict
Exploitable

## Source
The loop index `i` is derived from the loop counter itself without external input, but the loop bounds calculation `i <= n` contains an off-by-one error. The parameter `max_out` (the destination buffer capacity) is correctly used to calculate `n`, but the loop condition writes one element beyond the valid index range.

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
The vulnerability is an off-by-one error in the loop boundary. The original code uses `i <= n` as the loop condition, which causes the loop to write at indices 0 through n inclusive—one element past the end of the `out` buffer when n equals max_out (the buffer's capacity). The fix changes the loop condition to `i < n`, which restricts writes to valid indices 0 through n-1. This aligns with the C guidance principle: "Valid indices are 0 to size - 1: a loop written i <= size writes one element past the end of every buffer it touches." The destination buffer holds at most max_out elements, n is capped at max_out, so the loop must run from 0 to n-1 to stay within bounds.

## Behaviour changes
None. The loop now executes exactly n iterations instead of n+1, writing only the intended number of elements. The function still returns n and copies the same number of events; the fix only removes the extra out-of-bounds write that was corrupting adjacent memory.
