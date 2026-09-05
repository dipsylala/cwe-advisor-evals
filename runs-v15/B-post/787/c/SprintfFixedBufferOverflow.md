## Verdict

Exploitable. Attacker-controlled `username` and `message` parameters have no length cap and are formatted into a fixed 64-byte stack buffer with `sprintf`, which performs no bounds check. Sufficiently long inputs overflow the buffer and corrupt the saved frame pointer and return address on the stack.

## Source

The vulnerability flows from two untrusted sources in the `log_user_action` function:
- `username`: a display name from an authenticated request handler, attacker-controlled in length
- `message`: a free-text status message from an authenticated request handler, attacker-controlled in length

Both are concatenated with locally-generated `timestamp` (bounded to 32 bytes by `strftime`) and fixed format strings into a 64-byte destination.

## Fix

**Vulnerable code:**

```c
char line[64];

// SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
sprintf(line, "[%s] %s: %s", timestamp, username, message);

FILE *fp = fopen("audit.log", "a");
if (fp == NULL) {
    return -1;
}

fputs(line, fp);
fputc('\n', fp);
fclose(fp);
return 0;
```

**Fixed code:**

```c
char line[64];

int written = snprintf(line, sizeof(line), "[%s] %s: %s", timestamp, username, message);
if (written < 0 || (size_t)written >= sizeof(line)) {
    /* Log entry would be truncated or encoding error; reject it */
    return -1;
}

FILE *fp = fopen("audit.log", "a");
if (fp == NULL) {
    return -1;
}

fputs(line, fp);
fputc('\n', fp);
fclose(fp);
return 0;
```

## Explanation

The fix replaces `sprintf` with `snprintf`, which takes an explicit destination capacity (`sizeof(line)`) and enforces it. `snprintf` returns the number of bytes written (or would have been written if the buffer were large enough). The check `(size_t)written >= sizeof(line)` catches both truncation (return value >= capacity) and encoding errors (negative return value cast to a large unsigned value). If the formatted log line cannot fit in the 64-byte buffer, the function rejects the operation and returns -1, preventing the out-of-bounds write. This replaces an unchecked unbounded write with a bounds-validated operation that fails safely when the input exceeds the destination capacity.

## Behaviour changes

1. **Return value on truncation**: The original code silently writes a truncated line and returns 0. The fixed code detects when the formatted output would exceed 64 bytes, returns -1 to signal failure, and discards the log entry. This is intentional—per CWE-787 remediation guidance, the fix should reject rather than truncate when untrusted input does not fit.

2. **Rejection of oversized logs**: Any log where the concatenated `[timestamp] username: message` exceeds 63 characters (due to the 64-byte buffer and NUL terminator) is now rejected. This prevents silent truncation and data loss, but changes the application behavior from "always log, possibly truncated" to "only log if it fits untruncated."

3. **Error handling**: The caller can now distinguish a file-open failure (`fopen` returned -1) from a log-entry rejection (the new snprintf check returns -1). Both return the same code, but the log message is not written in either case.
