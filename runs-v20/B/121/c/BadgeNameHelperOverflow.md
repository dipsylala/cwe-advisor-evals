## Verdict

Confirmed. `append_display_name` writes into a fixed-size stack buffer using unbounded `strcpy`/`strcat`, with no check that the combined input fits.

## Source

`first` and `last`, the `const char *` name-part parameters of `render_badge_line`, are attacker/user-controlled name fields with no declared length limit. They flow unchanged into `append_display_name(display_name, first, last)`.

## Fix

### File: BadgeNameHelperOverflow.c

```c
#include <stdio.h>
#include <string.h>

static int append_display_name(char *destination, size_t destination_size, const char *first, const char *last) {
    int written = snprintf(destination, destination_size, "%s %s", first, last);
    if (written < 0 || (size_t)written >= destination_size) {
        return -1;
    }
    return 0;
}

void render_badge_line(const char *first, const char *last, char *out) {
    char display_name[32];
    if (append_display_name(display_name, sizeof display_name, first, last) != 0) {
        out[0] = '\0';
        return;
    }
    strcpy(out, display_name);
}
```

## Explanation

`render_badge_line` declares `display_name[32]` and hands the raw pointer to `append_display_name`, where `destination` has already decayed to `char *` - `sizeof(destination)` inside that function would yield the pointer size, not 32, so the original code had no way to know the real capacity and used unbounded `strcpy` followed by `strcat`, letting any `first`/`last` combination longer than 31 characters overflow the stack buffer.

The fix passes the destination's real capacity (`sizeof display_name`, taken in the scope where the array is declared) into `append_display_name` as an explicit parameter, then replaces the `strcpy`+`strcat` pair with a single bounded `snprintf(destination, destination_size, "%s %s", first, last)`, which formats and null-terminates within that capacity in one call and reports via its return value the length it would have needed. Per the loaded C guidance, an over-length input is rejected rather than silently truncated: when `snprintf`'s return indicates the formatted name did not fit, `append_display_name` returns -1 instead of leaving a truncated (and therefore different) name in the buffer, and `render_badge_line` treats that as a rejection - it writes an empty string to `out` and returns, so no truncated or malformed name is ever forwarded downstream. This closes the CWE-121 write because the write can no longer exceed `destination_size` under any input, while normal-length names still flow through unchanged as before.

## Behaviour changes

- `append_display_name`'s signature changed from `(char *destination, const char *first, const char *last)` returning `void` to `(char *destination, size_t destination_size, const char *first, const char *last)` returning `int` (0 on success, -1 if the combined name did not fit), so the caller can distinguish success from rejection - required because the callee cannot recover the destination's real size on its own once it decays to a pointer.
- Previously, a `first`+`" "`+`last` combination of 32 or more characters silently overflowed the stack (undefined behaviour, potentially exploitable). Now such input is rejected: `render_badge_line` writes an empty string to `out` instead of a badge line. Names that fit within 31 characters plus the joining space and terminator behave exactly as before, byte-for-byte.
