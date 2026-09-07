## Verdict

**Confirmed**: Stack-based buffer overflow at line 6 via unbounded `strcat()` into a fixed-size stack buffer with no size parameter to `append_display_name()`.

Assumption: `first` and `last` parameters are untrusted and may be attacker-controlled (e.g., from user input or network).

## Source

`first` and `last` parameters enter `render_badge_line()` from an untrusted source. They flow into `append_display_name(display_name, first, last)` at line 11, where `display_name` is a 32-byte fixed-size stack buffer.

## Fix

The vulnerability is that `append_display_name()` receives only a pointer to the destination buffer, with no size information. It uses unbounded string functions (`strcpy` and `strcat`) that cannot know how much space is available. Combined input of `first` and `last` longer than ~30 bytes (accounting for space separator and null terminator) will overflow the 32-byte buffer.

**Fixed code:**

### File: BadgeNameHelperOverflow.c

```c
#include <string.h>
#include <stdio.h>

static int append_display_name(char *destination, size_t dest_size, const char *first, const char *last) {
    int written = snprintf(destination, dest_size, "%s %s", first, last);
    if (written < 0 || (size_t)written >= dest_size) {
        return 0;  // Truncation detected, reject oversized input
    }
    return 1;  // Success
}

void render_badge_line(const char *first, const char *last, char *out) {
    char display_name[32];
    if (!append_display_name(display_name, sizeof(display_name), first, last)) {
        // Reject input that does not fit; clear output and return
        if (out) out[0] = '\0';
        return;
    }
    strcpy(out, display_name);
}
```

## Explanation

The fix replaces the unbounded `strcpy()` and `strcat()` sequence with `snprintf()`, which takes an explicit size parameter (`dest_size`) and enforces the destination buffer's capacity. The function now:

1. **Accepts a size parameter**: `append_display_name()` now receives `dest_size`, allowing it to validate bounds.
2. **Uses `snprintf()` instead of `strcpy()`/`strcat()`**: A single bounded call eliminates the accumulating overflow risk of sequential unbounded operations.
3. **Validates the result**: Checks that `snprintf()` did not truncate (test: `(size_t)written >= dest_size` indicates truncation).
4. **Rejects oversized input**: Rather than silently truncating, the function rejects input longer than the buffer can hold and returns an error code.
5. **Passes size at the call site**: Line 11 now uses `sizeof(display_name)`, ensuring the actual buffer size is used, not a hardcoded constant that can drift.

The fix follows CWE-121's C guidance: "Prefer one bounded `snprintf(dest, sizeof dest, "%s%s", a, b)` over `strcpy` followed by `strcat`" and "Validate the length and reject before copying rather than truncating."

## Behaviour changes

- **Input validation**: Calls with combined `first`+`last` length exceeding 30 bytes (buffer size minus 1 for null terminator) are now rejected instead of overflowing.
- **Output on rejection**: When input is too long, the output buffer `out` is cleared to an empty string instead of containing corrupted or undefined data.
- **Return value**: `append_display_name()` now returns `int` (1 for success, 0 for truncation detected) so the caller can decide how to handle oversized input.
- **No silent truncation**: Legitimate callers passing oversized strings will detect the rejection and can log/handle the error appropriately, rather than silently receiving a truncated name.
