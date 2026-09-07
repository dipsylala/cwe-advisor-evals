## Verdict

Exploitable. The `username` and `action` parameters are user-controlled and copied unbounded into a 64-byte stack buffer via `strcpy` and `strcat` without length validation, allowing a stack-based buffer overflow.

## Source

Parameters `username` and `action` (untrusted, user-provided) flow directly into the `message` buffer at line 11 via `strcpy`, then line 14 via `strcat`, with no validation that the combined length fits the 64-byte capacity.

## Fix

**Vulnerable code:**
```c
int build_audit_message(const char *username,
                        const char *action,
                        char *out,
                        size_t out_capacity)
{
    char message[64];

    strcpy(message, username);           // Unbounded copy
    strcat(message, ":");
    strcat(message, action);             // Unbounded concatenation

    int written = snprintf(out, out_capacity, "AUDIT %s", message);
    if (written < 0 || (size_t)written >= out_capacity) {
        return -1;
    }
    return 0;
}
```

**Fixed code:**
```c
int build_audit_message(const char *username,
                        const char *action,
                        char *out,
                        size_t out_capacity)
{
    char message[64];

    int needed = snprintf(message, sizeof(message), "%s:%s", username, action);
    if (needed < 0 || (size_t)needed >= sizeof(message)) {
        return -1;
    }

    int written = snprintf(out, out_capacity, "AUDIT %s", message);
    if (written < 0 || (size_t)written >= out_capacity) {
        return -1;
    }
    return 0;
}
```

## Explanation

The fix replaces the three unsafe `strcpy`/`strcat` calls with a single bounded `snprintf` that safely formats `username`, `":", and `action` into the 64-byte `message` buffer. The function then validates the result: if `snprintf` reports truncation (return value >= buffer size) or error, the entire operation is rejected and -1 is returned to the caller. This prevents any buffer overflow while rejecting oversized input rather than truncating it silently. The final `snprintf` call and its validation logic remain unchanged. The function's return contract is preserved: it returns -1 on any error (including input too large for the buffer or output too large for the caller's buffer) and 0 on success.

## Behaviour changes

None. The function rejects oversized input by returning -1, matching the existing error-handling contract. The final `snprintf` call, its return-value check, and the function's overall contract remain unchanged.
