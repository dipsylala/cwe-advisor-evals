## Verdict
Real stack-based buffer overflow vulnerability.

## Source
Lines 11-14 use unbounded string operations on a fixed 64-byte stack buffer:
- Line 11: `strcpy(message, username)` copies without size limits
- Line 12: `strcat(message, ":")` appends without bounds checking
- Line 14: `strcat(message, action)` appends without bounds checking

If `username` or `action` are sufficiently long, they overflow the `message` buffer.

## Fix
Replace unbounded `strcpy()` and `strcat()` with `snprintf()`:

```c
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
The `snprintf()` function enforces the buffer size limit (`sizeof(message)`) and prevents overflow by either truncating or rejecting input that exceeds the available space. The added validation check ensures that construction of the intermediate `message` buffer succeeds before proceeding to build the final output. This matches the existing pattern used at line 16-18 for the output buffer and eliminates the unbounded string operations that created the overflow risk.
