## Verdict

exploitable

## Source

- `timestamp` parameter: locally generated via `strftime()` in main, but the function parameter has no enforced length constraint
- `username` parameter: explicitly noted as "attacker-controlled in length"
- `message` parameter: explicitly noted as "attacker-controlled in length"

## Fix

**Vulnerable code:**

```c
int log_user_action(const char *timestamp, const char *username, const char *message)
{
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
}
```

**Fixed code:**

```c
int log_user_action(const char *timestamp, const char *username, const char *message)
{
    char line[64];

    int written = snprintf(line, sizeof(line), "[%s] %s: %s", timestamp, username, message);
    if (written < 0 || (size_t)written >= sizeof(line)) {
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
}
```

## Explanation

The vulnerability occurs because `sprintf()` performs unbounded formatted output into a fixed 64-byte buffer. If the combined length of the format string overhead (`[]` and `: ` twice), `timestamp`, `username`, and `message` exceeds 63 characters (accounting for the null terminator), the write overflows the buffer boundary.

The fix replaces `sprintf()` with `snprintf()`, which takes an explicit buffer size parameter and enforces it as a hard limit. The function returns the number of characters written (or negative on encoding error), which is then validated: a return value at or above the buffer size indicates truncation. The cast to `(size_t)` is necessary because negative return values would become large unsigned values in the size comparison, correctly triggering the failure path. When truncation is detected, the function returns -1 (error) before proceeding to file I/O, preventing any use of the incomplete or malformed log entry.

## Behaviour changes

The fixed code adds explicit truncation checking where the original code silently overflowed. When `snprintf()` truncates because the formatted output exceeds 63 bytes:

- **Original**: Buffer overflows; memory corruption occurs; undefined behavior follows
- **Fixed**: Truncation is detected; function returns -1 (error) to the caller; no partial/corrupted log entry is written

The caller of `log_user_action()` should inspect the return value: 0 indicates success, -1 indicates either file open failure or format truncation. The existing caller in `main()` already ignores the return value, but this now allows error detection in production use. No changes are required to the function's signature or callers; the behavior change only becomes visible if the caller chooses to check for failure, which is the safe pattern for production systems.
