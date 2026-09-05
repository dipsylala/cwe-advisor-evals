## Verdict

CONFIRMED. The code uses unbounded string concatenation (`strcpy`, `strcat`) into a fixed-size stack buffer without length validation, allowing external input to overflow the 32-byte `display_name` buffer.

## Source

The vulnerability originates in the `render_badge_line` function, which receives untrusted `first` and `last` parameters from a caller. These parameters are passed to `append_display_name`, which concatenates them via:
- Line 4: `strcpy(destination, first)` – copies first name without length check
- Line 5: `strcat(destination, " ")` – appends space
- Line 6: `strcat(destination, last)` – appends last name without length check

The `destination` parameter points to `display_name[32]`, a 32-byte stack buffer. If the combined length of `first + " " + last` exceeds 31 bytes (plus null terminator), the buffer overflows, corrupting adjacent stack memory.

## Fix

Replace the unbounded string operations with `snprintf`, which enforces a size limit on the output. The function must also accept the destination buffer size as a parameter, since the current signature has no way to know it.

**Fixed code:**

```c
#include <string.h>
#include <stdio.h>

static void append_display_name(char *destination, size_t dest_size, const char *first, const char *last) {
    snprintf(destination, dest_size, "%s %s", first, last);
}

void render_badge_line(const char *first, const char *last, char *out) {
    char display_name[32];
    append_display_name(display_name, sizeof(display_name), first, last);
    strcpy(out, display_name);
}
```

## Explanation

The fix replaces three separate unbounded operations (`strcpy`, `strcat`, `strcat`) with a single `snprintf` call that formats the concatenated string while respecting the destination buffer size. The `snprintf` function guarantees that no more than `dest_size` bytes (including the null terminator) will be written, preventing the overflow.

Key changes:
1. Added `#include <stdio.h>` for `snprintf`
2. Modified `append_display_name` to accept `dest_size` as a parameter
3. Replaced the three separate string operations with `snprintf(destination, dest_size, "%s %s", first, last)`
4. Updated the call site to pass `sizeof(display_name)` so the function knows the buffer's actual capacity

The `snprintf` function ensures the output is null-terminated and reports truncation via its return value (if needed for validation). In this case, if the formatted string would exceed 31 bytes of capacity, it is silently truncated—which is acceptable for a display name context where oversized input is rejected by length, not preserved.

## Behaviour changes

- **Buffer overflow eliminated**: The 32-byte buffer can no longer be overflowed, regardless of input length.
- **Truncation instead of crash**: If `first` and `last` together exceed 30 characters (leaving 1 for the null terminator and 1 for the space), the name is silently truncated to fit. No error is signaled. If stricter input validation is desired, check the return value of `snprintf` against the destination size: `if (snprintf(...) >= dest_size) { /* input too long, reject */ }`.
- **Function signature change**: `append_display_name` now requires a third parameter (`dest_size`). Any caller of this function must be updated to pass the destination buffer size. In this code, only `render_badge_line` calls it, so the change is localized.
- **Header dependency**: The fix adds a dependency on `<stdio.h>` for `snprintf`.
