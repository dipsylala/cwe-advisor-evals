## Verdict

The finding is **valid**. The code uses unbounded `strcpy()` and `strcat()` to write attacker-controlled `first` and `last` strings into a 32-byte stack buffer without validating their combined length, enabling a stack-based buffer overflow.

## Source

The vulnerability originates from function parameters `first` and `last` passed to `append_display_name()` at line 3, which flow unvalidated into the destination buffer.

**Call chain:**
- `render_badge_line()` receives caller-controlled `first` and `last`
- Passes them to `append_display_name()` 
- `strcpy(destination, first)` writes `first` into the 32-byte `display_name` buffer without bounds checking
- `strcat(destination, " ")` appends a space
- `strcat(destination, last)` appends `last` to the partially-filled buffer

If the combined length of `first + " " + last` exceeds 31 bytes (32 minus the NUL terminator), the write overflows the stack buffer.

## Fix

Replace the unbounded `strcpy()` and `strcat()` sequence with a single bounded `snprintf()` call that validates all three components and enforces the destination size:

```c
#include <stdio.h>
#include <string.h>

static int append_display_name(char *destination, size_t dest_size, const char *first, const char *last) {
    int written = snprintf(destination, dest_size, "%s %s", first, last);
    if (written < 0 || (size_t)written >= dest_size) {
        return -1;  // Truncation or encoding error
    }
    return 0;  // Success
}

void render_badge_line(const char *first, const char *last, char *out) {
    char display_name[32];
    if (append_display_name(display_name, sizeof(display_name), first, last) != 0) {
        // Handle error: input too long for buffer
        out[0] = '\0';
        return;
    }
    strcpy(out, display_name);
}
```

## Explanation

The fix replaces three separate unbounded string operations with a single `snprintf()` call. `snprintf()` takes an explicit `dest_size` parameter and enforces bounds on the entire formatted output, including the NUL terminator. It formats `first`, a space, and `last` into the destination in a single bounded write.

The check `if (written < 0 || (size_t)written >= dest_size)` detects both encoding errors (negative return) and truncation (the formatted length would have met or exceeded the buffer capacity). This allows the caller to reject oversized input rather than silently truncating it to an incorrect value.

The function signature change adds a `dest_size` parameter to enforce the size at each call site, preventing the caller from passing incorrect sizes. This follows the C-specific guidance: "Reject oversized input explicitly rather than silently truncating it" and "use the destination buffer's actual declared size in the length check, never a separate hardcoded constant."

Note: `render_badge_line()` still uses `strcpy(out, display_name)` at line 12. If `out` has a bounded size, that line should also be replaced with `snprintf()` or explicit bounds validation. The immediate overflow is closed at the 32-byte buffer; downstream usage of `out` depends on its own caller's contract.

## Behaviour changes

- **Input validation**: Oversized input (where `first + " " + last` exceeds 31 characters) is now rejected with an error return, rather than silently overflowing the buffer.
- **Error reporting**: The function now returns an error code so the caller can detect when input is too long and handle it appropriately.
- **Buffer safety**: All writes into the destination buffer are bounded by the `dest_size` parameter passed to `snprintf()`.
- **Function signature**: `append_display_name()` now takes an additional `dest_size` parameter, which must be supplied by the caller.
