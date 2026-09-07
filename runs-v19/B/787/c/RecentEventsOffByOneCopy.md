## Verdict

Exploitable. Off-by-one loop condition allows writing one element past the end of the destination buffer.

## Source

The destination buffer capacity `max_out` and the derived count `n = min(history_len, max_out)` determine how many elements may be written to `out`. The source data comes from the `history` buffer.

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

The original loop condition `i <= n` iterates from 0 to n (inclusive), writing n+1 elements. Since n represents the count of elements to copy and is constrained to be at most max_out, the array `out` has capacity for indices 0 to max_out-1, or equivalently 0 to n-1. The loop iteration where i equals n writes to out[n], which is one element past the valid bounds.

The fix changes the loop condition to `i < n`, reducing the iteration count from n+1 to n. Valid writes now span indices 0 through n-1, staying within the destination buffer's allocated capacity. This matches the function's documented contract: "copies at most max_out of the most recent entries" and "returns the number of entries copied."

Per CWE-787 C guidance, valid indices for a buffer are 0 to size-1; a loop written i <= size writes one element past the end. This is the textbook pattern the guidance identifies and corrects.

## Behaviour changes

The loop now executes n iterations instead of n+1. The return value correctly reflects the number of elements actually written. The function maintains its contract: it copies n elements (where n = min(history_len, max_out)) to the destination buffer and returns n. The fix does not alter the data flow, return type, or any other aspect of the function's interface beyond closing the out-of-bounds write.

