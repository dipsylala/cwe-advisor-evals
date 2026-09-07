## Verdict

Confirmed stack-based buffer overflow. The 32-byte `display_name` buffer on line 10 receives unbounded concatenation of externally-controlled `first` and `last` parameters via `strcpy()` and `strcat()` calls with no length validation.

## Source

The vulnerability is reachable when:
- `render_badge_line()` is called with attacker-controlled `first` and `last` parameters
- `first` and `last` have no length constraints enforced by the caller
- Combined length of `first`, space separator, and `last` exceeds 31 bytes (accounting for NUL terminator)
- The 32-byte stack buffer `display_name` overflows, corrupting adjacent stack memory

## Fix

Replace the unbounded `strcpy()` and `strcat()` sequence in `append_display_name()` with a single `snprintf()` call that enforces the destination buffer's size, and reject input that exceeds capacity.

Change the function signature to accept the destination buffer size:

```c
#include <string.h>
#include <stdio.h>

static void append_display_name(char *destination, size_t dest_size, const char *first, const char *last) {
    int written = snprintf(destination, dest_size, "%s %s", first, last);
    // snprintf returns the number of bytes that would have been written (excluding NUL).
    // If written >= dest_size, truncation occurred; reject the input.
    if (written < 0 || (size_t)written >= dest_size) {
        destination[0] = '\0';
        return;
    }
}

void render_badge_line(const char *first, const char *last, char *out) {
    char display_name[32];
    append_display_name(display_name, sizeof(display_name), first, last);
    strcpy(out, display_name);
}
```

## Explanation

The original code used `strcpy()` to copy `first`, then two `strcat()` calls to append a space and `last`. These functions have no size argument and continue writing until a NUL terminator is encountered in the source, ignoring the destination buffer's 32-byte capacity. If the combined length of `first + " " + last` exceeds 31 bytes, the write continues past the buffer boundary, overflowing the stack.

The fix uses `snprintf()`, which takes an explicit `dest_size` argument and internally enforces the boundary. It returns the count of bytes that would have been written; if this count is >= `dest_size`, truncation occurred, indicating the input was too long for the buffer. The fix rejects such input by clearing the destination buffer rather than silently truncating, which prevents the caller from using a malformed or incomplete name value downstream.

The function now requires the caller to pass the destination buffer's actual size via `sizeof(display_name)`, ensuring the bound cannot drift out of sync with the actual array. This is the safe pattern identified in CWE-121 guidance for C.

## Behaviour changes

- **Input validation**: Oversized input (combined length >= 32 bytes) is now explicitly rejected. The destination buffer is cleared (`destination[0] = '\0'`) on rejection, signaling to the caller that formatting failed.
- **No silent truncation**: The original code would silently truncate the last name if the combined string was too long. The fix replaces that with rejection, preventing the caller from treating truncated data as a complete name.
- **Function signature change**: `append_display_name()` now requires a third parameter (`dest_size`). Callers must be updated to pass `sizeof(display_name)` when calling this function.
- **Return value**: The original function returned `void`. The fix continues to return `void`, but uses the destination buffer's first byte being NUL to signal failure to the caller (a distinct pattern from the space-separated name that would be present on success).
