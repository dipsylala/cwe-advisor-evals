## Verdict

Exploitable. The function uses `strcpy()` and `strcat()` without any bounds checking against the destination buffer. Both `username` and `action` parameters are untrusted external inputs, and their combined length with the colon separator is not validated against the 64-byte `message` buffer before writing.

## Source

Untrusted parameters:
- `username` (from caller via parameter, line 4)
- `action` (from caller via parameter, line 5)

## Fix

### File: StackAuditMessageOverflow.c

```c
#include <stdio.h>
#include <string.h>

int build_audit_message(const char *username,
                        const char *action,
                        char *out,
                        size_t out_capacity)
{
    char message[64];

    // Use snprintf to safely format with bounds checking
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

The fix replaces the unbounded `strcpy()` and two `strcat()` calls with a single bounded `snprintf()` call that formats the message buffer with explicit size checking. This follows the C-specific guidance principle: "Prefer one bounded `snprintf(dest, sizeof dest, "%s%s", a, b)` over `strcpy` followed by `strcat` - it bounds both operands and the terminator in a single call and reports the length it would have needed, so truncation is detectable via `written < 0 || (size_t)written >= sizeof dest`."

The first `snprintf()` validates that `username` + ":" + `action` fits within the 64-byte buffer and rejects the input (returns -1) if it does not. The truncation detection `(size_t)written >= sizeof(message)` ensures the function fails safely when combined input exceeds capacity, rather than silently truncating or overflowing.

## Behaviour changes

The function now rejects calls where the formatted message exceeds the 64-byte buffer. Previously, such inputs would overflow the stack. The function still returns -1 on error (matching the original contract), but now rejects oversized input before the copy rather than corrupting memory. The `written` variable is reused for both format operations, which is safe because the first operation's result is checked before proceeding to the second.
