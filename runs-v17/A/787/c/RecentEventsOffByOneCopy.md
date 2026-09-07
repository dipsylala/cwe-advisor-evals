## Verdict
CWE-787 (Out-of-bounds Write) confirmed at line 15. The loop condition `i <= n` iterates one time too many, writing out[n] when the buffer `out` is sized for indices 0 through n-1.

## Source
The vulnerable code at line 15:
```c
for (size_t i = 0; i <= n; i++) {
```

When `n` equals `max_out` (the size of the output buffer), the loop iterates n+1 times, accessing `out[n]` which is beyond the buffer bounds.

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
The loop condition must be `i < n` instead of `i <= n` to iterate exactly n times. With `n` as the number of elements to copy and `out` sized to hold `max_out` elements, valid indices for `out` are 0 through n-1 (since n <= max_out). The condition `i <= n` causes a write to out[n], which exceeds the buffer bounds. The fix ensures the loop writes exactly n elements into valid indices 0 through n-1.
