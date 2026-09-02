## Verdict

Exploitable. The `strcat` at line 6 writes unbounded data into a fixed-size 32-byte stack buffer without validating that `first`, a space, and `last` combined fit within the destination. An attacker controlling `first` and `last` can overflow the buffer and corrupt the stack.

## Source

Line 9: `const char *first` and `const char *last` parameters in `render_badge_line` are untrusted caller-supplied input. Line 11 passes these to `append_display_name` without length validation.

## Fix

**Vulnerable code (lines 3–7):**
```c
static void append_display_name(char *destination, const char *first, const char *last) {
    strcpy(destination, first);
    strcat(destination, " ");
    strcat(destination, last);
}
```

**Fixed code:**
```c
static void append_display_name(char *destination, size_t dest_size, const char *first, const char *last) {
    snprintf(destination, dest_size, "%s %s", first, last);
}
```

**Updated call site (line 11):**
```c
append_display_name(display_name, sizeof(display_name), first, last);
```

## Explanation

The fix replaces three separate unbounded operations (`strcpy`, `strcat`, `strcat`) with a single `snprintf` call that enforces the destination size. `snprintf` bounds all operands (both `first` and `last`) and the space separator within the destination buffer's actual declared capacity, automatically handling truncation and null termination. The function signature now explicitly accepts `dest_size`, passing the 32-byte capacity explicitly at the call site; this ensures the function cannot accidentally receive a decayed pointer and `sizeof()` result in 4 or 8 bytes. The fix rejects oversized input by truncating it safely rather than overflowing the stack.

## Behaviour changes

- Added `size_t dest_size` parameter to `append_display_name` to receive the buffer capacity explicitly. This is necessary because after the buffer is passed as a parameter, the pointer decays and `sizeof()` no longer yields the array's true size.
- Changed from three separate string operations to a single `snprintf` call. The new behavior automatically handles all termination and bounds checking; the old code relied on three separate unchecked operations that must each fit within what previous operations left available.
- Oversized input is now truncated silently by `snprintf` rather than overflowing. This is the safe truncation pattern recommended by the guidance: reject the oversized input explicitly where possible, but where silent truncation is acceptable, `snprintf` is the safe choice.
