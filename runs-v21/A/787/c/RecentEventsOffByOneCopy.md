## Verdict
CONFIRMED

## Source
```c
size_t copy_recent_events(const Event *history, size_t history_len, Event *out, size_t max_out)
{
    size_t n = history_len < max_out ? history_len : max_out;
    size_t start = history_len - n;

    for (size_t i = 0; i <= n; i++) {
        out[i] = history[start + i];
    }

    return n;
}
```

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
The loop condition was changed from `i <= n` to `i < n` on line 15. When copying n entries into the output buffer, valid indices range from 0 to n-1. The original condition `i <= n` causes an extra iteration where i equals n, writing to `out[n]` which exceeds the bounds of the n-element region. The corrected condition ensures the loop executes exactly n times with indices 0 through n-1, writing all n entries without exceeding buffer bounds.
