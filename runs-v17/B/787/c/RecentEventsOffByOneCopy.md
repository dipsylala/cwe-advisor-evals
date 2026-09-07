## Verdict

The finding is confirmed. The loop condition at line 15 uses `i <= n` which causes an out-of-bounds write on the final iteration when i equals n. The destination buffer `out` has capacity for indices 0 through n-1, making index n an out-of-bounds write.

## Source

The vulnerability is in the loop bounds at line 15:

```c
for (size_t i = 0; i <= n; i++) {
    out[i] = history[start + i];
}
```

Where n represents the number of elements to copy, the loop iterates from 0 to n inclusive, writing to `out[0]` through `out[n]`. This is off-by-one: valid indices for n copied elements are 0 through n-1.

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

The fix changes the loop condition from `i <= n` to `i < n` at line 15. This ensures the loop iterates from 0 to n-1, which are the valid indices for an array of n elements. The C language guidance from CWE-787 explicitly identifies this pattern: "Valid indices are 0 to size - 1: a loop written i <= size writes one element past the end of every buffer it touches." By replacing `<=` with `<`, the write operation stays within the bounds of the destination buffer `out`, closing the out-of-bounds write vulnerability.

## Behaviour changes

The loop now writes exactly n elements instead of n+1 elements. The function return value (n) remains unchanged and correctly represents the number of elements actually copied. The function's contract—copying at most max_out of the most recent history entries—is preserved, and the buffer overflow is eliminated.

