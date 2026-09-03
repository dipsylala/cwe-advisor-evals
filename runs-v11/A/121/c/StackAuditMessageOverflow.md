## Verdict

Real: stack-based buffer overflow via unbounded string concatenation.

## Source

Lines 11-14 use `strcpy()` and `strcat()` on a 64-byte stack buffer without bounds checking. If `username` and `action` combined exceed 62 bytes (accounting for the colon and null terminator), the buffer overflows.

## Fix

```c
#include <stdio.h>
#include <string.h>

int build_audit_message(const char *username,
                        const char *action,
                        char *out,
                        size_t out_capacity)
{
    char message[64];

    int written = snprintf(message, sizeof(message), "%s:%s", username, action);
    if (written < 0 || (size_t)written >= sizeof(message)) {
        return -1;
    }

    written = snprintf(out, out_capacity, "AUDIT %s", message);
    if (written < 0 || (size_t)written >= out_capacity) {
        return -1;
    }
    return 0;
}
```

## Explanation

Replace `strcpy()` and `strcat()` with `snprintf()` to build the intermediate message safely. `snprintf()` enforces a size limit (`sizeof(message)`) and returns the number of characters that would have been written. Check that the result fits within the buffer; if it does not (written >= buffer_size), return an error. This prevents both the stack buffer overflow on `message` and ensures the output fits in the caller's buffer before writing to `out`.

