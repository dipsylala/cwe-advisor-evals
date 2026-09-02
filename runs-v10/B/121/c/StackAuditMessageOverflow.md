## Verdict

Exploitable. The stack buffer `message` (64 bytes, line 9) is written by unbounded `strcpy()` and `strcat()` calls without validating that `username` and `action` fit within the destination. An attacker controlling either parameter can overflow the buffer.

## Source

Function parameters `username` (line 4) and `action` (line 5) are untrusted sources. Both flow directly into stack-allocated `message` without length validation.

## Fix

**Vulnerable code:**
```c
char message[64];

strcpy(message, username);
strcat(message, ":");
// SAST FINDING: CWE-121 (Stack-based Buffer Overflow) reported here. Sink is the next statement.
strcat(message, action);

int written = snprintf(out, out_capacity, "AUDIT %s", message);
```

**Fixed code:**
```c
char message[64];

int len = snprintf(message, sizeof(message), "%s:%s", username, action);
if (len < 0 || (size_t)len >= sizeof(message)) {
    return -1;
}

int written = snprintf(out, out_capacity, "AUDIT %s", message);
```

## Explanation

Replace the three unbounded copy operations (`strcpy` + two `strcat` calls) with a single bounded `snprintf()` that formats both inputs into the destination buffer while enforcing the size limit. The `snprintf()` call validates that the formatted string (username + ":" + action + null terminator) fits within the 64-byte buffer. If the combined length would exceed capacity, `snprintf()` returns a value >= 64 (the buffer size), which is detected and rejected before any overflow can occur. This approach closes the overflow while preserving the function's contract: oversized input is explicitly rejected rather than silently truncated or corrupted.

## Behaviour changes

- **Oversized input handling**: The original code silently overwrites the stack when `username` + ":" + `action` exceeds 63 bytes. The fixed code explicitly rejects such input by returning -1, signalling to the caller that the audit message could not be built. This is a breaking change in behavior but is necessary to eliminate the security vulnerability. A caller encountering this error should log or reject the operation, not attempt retry or truncation.

- **No truncation**: The original `snprintf()` on line 16 would format a corrupted or incomplete `message` into `out` if the intermediate buffer overflowed. The fixed code ensures `message` always contains a complete, valid audit entry (or the function fails cleanly).

