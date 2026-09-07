## Verdict

**CWE-121: Stack-based Buffer Overflow - CONFIRMED**

The vulnerability exists at line 6 (and implicitly at lines 4-5) where `strcat()` writes into a fixed-size 32-byte stack buffer without validating that the combined length of `first`, `" "`, and `last` fits within that capacity. An attacker controlling `first` or `last` can overflow the stack.

## Source

The vulnerable sink is `strcat(destination, last)` at line 6 of `append_display_name()`. The function builds a display name by concatenating three parts into a 32-byte stack buffer with no length bounds:

- `strcpy(destination, first)` — copies first name unbounded
- `strcat(destination, " ")` — appends space
- `strcat(destination, last)` — appends last name unbounded

Both `strcpy` and `strcat` determine their write length by scanning the source string for a terminator, paying no attention to the destination buffer's capacity. The 32-byte buffer at line 10 is easily overflowed by names that individually fit within a reasonable size but combine to exceed 32 bytes when concatenated with a space.

## Fix

Replace `append_display_name()` to use `snprintf()`, which enforces the destination buffer's actual size and detects truncation in a single bounded call:

```c
static int append_display_name(char *destination, size_t dest_size, const char *first, const char *last) {
    int written = snprintf(destination, dest_size, "%s %s", first, last);
    if (written < 0 || (size_t)written >= dest_size) {
        return -1;  // Truncation or error
    }
    return 0;
}

void render_badge_line(const char *first, const char *last, char *out) {
    char display_name[32];
    if (append_display_name(display_name, sizeof display_name, first, last) != 0) {
        // Handle error: input too long for buffer
        out[0] = '\0';
        return;
    }
    strcpy(out, display_name);
}
```

## Explanation

**What changed:**

1. `snprintf()` replaces `strcpy()` and `strcat()` — it formats the concatenated string in one call and respects the destination's `sizeof(destination)` parameter.

2. The function now accepts a `dest_size` parameter so the caller's buffer size is enforced at the write point, preventing the mistake of passing a mismatched size constant.

3. `snprintf()` returns the number of characters *written* (excluding terminator). If `written >= dest_size`, the output was truncated, so the function returns an error code instead of silently losing data.

4. The caller now checks the return value and handles oversized input by rejecting it (clearing the buffer and returning early) rather than proceeding with corrupted data.

**Why this is correct:**

- `snprintf()` enforces the destination buffer's capacity: it will write at most `dest_size - 1` characters plus a terminator, with no possibility of overflow.
- The `sizeof dest_size` argument is the actual declared size of `display_name[32]`, not a hardcoded constant that could drift.
- The return check (`written >= dest_size`) detects truncation so the caller knows the input was too long and can reject it instead of treating partial data as valid.
- Per CWE-121's guidance: "Reject oversized input explicitly rather than silently truncating it."

## Behaviour changes

- **Overflow eliminated:** Input exceeding 30 characters (31 with space, 32 with terminator) now returns an error instead of overflowing the stack.
- **Input validation:** The caller now knows when input is too long and can log, reject, or alert on the oversized data.
- **Error propagation:** A return value of `-1` signals that the badge name could not be built, allowing the caller to handle the failure case (e.g., use a placeholder name, truncate with an indicator, or log a security event).
- **Security-in-depth:** The function is now safe even if called from different contexts with different buffer sizes, because the size is always passed explicitly and checked at the write point.
