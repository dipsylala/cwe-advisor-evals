## Verdict

**CWE-787: Out-of-bounds Write**

The vulnerability is real and exploitable. The `sprintf()` call at line 16 writes formatted output into a fixed 64-byte buffer without checking the destination capacity. The inputs (`username` and `message`) are documented as attacker-controlled with no length cap, and they flow directly into the format string without validation. An attacker can supply username and message values that, when formatted with the "[", "]: " overhead, exceed the buffer size and corrupt memory beyond the allocation.

## Source

- **Untrusted inputs**: `username` and `message` parameters to `log_user_action()`. Both originate from request handler fields with no length constraints (as stated in the function's comment).
- **Trusted input**: `timestamp` is locally generated in `main()` and bounded to 32 characters via `strftime()` with a fixed format, so it does not contribute to the overflow risk.

The vulnerability path: `username` → parameter → format argument to `sprintf()` → memory write. Same for `message`.

## Fix

Replace line 16:

```c
// Original (vulnerable):
sprintf(line, "[%s] %s: %s", timestamp, username, message);

// Fixed:
int written = snprintf(line, sizeof(line), "[%s] %s: %s", timestamp, username, message);
if (written < 0 || (size_t)written >= sizeof(line)) {
    return -1;
}
```

After line 16, the fixed code validates the return value before continuing. If `snprintf()` returns a negative value (encoding error) or a value >= 64 (output was truncated or did not fit), the function rejects the log entry and returns -1 to signal failure.

## Explanation

`sprintf()` has no mechanism to limit output to the destination buffer's capacity. It writes until the format string is exhausted, corrupting memory if the output exceeds the buffer size. `snprintf()` takes an explicit size parameter (`sizeof(line)`) and truncates the output to fit, always NUL-terminating the result. 

The return value of `snprintf()` indicates how many bytes would have been written had the buffer been large enough. By checking `written >= sizeof(line)`, the code detects truncation and can reject a malformed audit log entry rather than silently truncating user input. The check for `written < 0` catches encoding errors in the format string or arguments.

This fix enforces the safe pattern from CWE-787 guidance for C: "use `snprintf` for formatted output... compare the return value against `sizeof(dest)` and treat a value at or above it as failure." The 64-byte buffer is still small, so a long username or message will be truncated, but the overflow is eliminated and the failure is detected.

## Behaviour changes

- **Truncation detection**: The fixed code now returns -1 if the formatted output does not fit in the 64-byte buffer. The original code would silently overflow memory.
- **Log completeness**: If a username or message is very long, the audit log entry is rejected entirely (function returns -1) rather than being written with corrupted data. A caller can check the return value and handle this (e.g., retry with a smaller message, or reject the oversized input upstream).
- **Return value significance**: The caller must now handle the -1 return to know whether the log operation succeeded. This is a functional change but necessary to avoid silent data corruption.
