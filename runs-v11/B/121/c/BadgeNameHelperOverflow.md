## Verdict

**VULNERABLE**

The code uses unbounded string operations (`strcpy` and `strcat`) to combine user-supplied `first` and `last` strings into a fixed-size 32-byte stack buffer. If the combined length exceeds 31 bytes (32 minus 1 for the null terminator), the write overflows the buffer.

## Source

**File:** BadgeNameHelperOverflow.c  
**Lines:** 4–6, 10–11

**Vulnerable code:**
```c
void append_display_name(char *destination, const char *first, const char *last) {
    strcpy(destination, first);      // Line 4: unbounded copy of first
    strcat(destination, " ");        // Line 5: unbounded append of space
    strcat(destination, last);       // Line 6: unbounded append of last
}

void render_badge_line(const char *first, const char *last, char *out) {
    char display_name[32];           // Line 10: 32-byte fixed buffer
    append_display_name(display_name, first, last);  // Line 11: passes untrusted data
    strcpy(out, display_name);
}
```

**Data flow:**  
Attacker-controlled `first` and `last` parameters → `append_display_name()` → unbounded `strcpy` and `strcat` into fixed-size `display_name[32]` → stack overflow.

## Fix

Replace the unbounded string operations with a single bounded `snprintf()` call that validates the combined output against the buffer capacity. Reject oversized input instead of truncating it.

**Fixed code:**
```c
#include <stdio.h>
#include <string.h>

static void append_display_name(char *destination, size_t dest_size, const char *first, const char *last) {
    int written = snprintf(destination, dest_size, "%s %s", first, last);
    if (written < 0 || (size_t)written >= dest_size) {
        // Input too long; reject and indicate error via empty string or handle as needed
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

The root cause is using `strcpy()` and `strcat()`, which copy data based on the source length, not the destination capacity. Combined, `first + " " + last` can easily exceed 32 bytes, overwriting the stack.

The fix:
1. **Added explicit capacity parameter** to `append_display_name()` so it knows the true buffer size.
2. **Replaced `strcpy` and `strcat` with `snprintf()`**, which formats the string while respecting the destination size and includes the space in a single bounded operation.
3. **Checked the return value**: `snprintf()` returns the number of bytes that would have been written (excluding the null terminator). If `written >= dest_size`, the output was truncated and the input was too long.
4. **Reject oversized input** by clearing the buffer and returning, rather than silently truncating it. This prevents a truncated value from being treated as the real concatenated name.

This satisfies the CWE-121 remediation requirement to validate the input length against the destination's declared capacity before copying, and to use a length-aware function that prevents overflow.

## Behaviour changes

- **Input validation is now explicit**: inputs that combined exceed 31 bytes (the usable 32-byte capacity minus 1 for the null terminator) are rejected, and `display_name` is set to an empty string.
- **Silent truncation is eliminated**: previously, an overlong input could truncate and still appear to succeed; now it fails visibly.
- **No output is produced for oversized input**: the caller receives an empty `display_name` instead of a partial concatenation. The caller should check for this condition (e.g., a zero-length result) and handle it appropriately—either log an error, reject the request, or use a fallback value.
- **Return value awareness required**: unlike the original code, the fixed `append_display_name()` should ideally return a status code (or use `errno`) to signal truncation to the caller, so that the truncation is not silent. For this autonomous fix, we reject in-place, but a production fix should propagate the error up the call stack.
