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

    for (size_t i = 0; i <= n; i++) {
        // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
        out[i] = history[start + i];
    }

    return n;
}
