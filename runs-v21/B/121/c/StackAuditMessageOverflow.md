## Verdict

Exploitable

## Source

The `username` and `action` parameters are untrusted inputs from the function caller with no documented length constraints.

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

    // Use snprintf to safely format with bounds checking instead of strcpy/strcat
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

The original code used unbounded copy operations (`strcpy` and `strcat`) to concatenate untrusted inputs into a fixed 64-byte stack buffer. An attacker supplying a sufficiently long `username` or `action` parameter would overflow the buffer and corrupt adjacent stack memory. The fix replaces the three separate operations—`strcpy(message, username)`, `strcat(message, ":")`, and `strcat(message, action)`—with a single `snprintf(message, sizeof(message), "%s:%s", username, action)` call. This enforces a destination-size limit on all inputs in one operation and detects truncation via the return value. The first check validates that the intermediate message buffer can hold the combined username and action; if truncation would occur, the function returns -1 and does not proceed. This rejection prevents the downstream code from operating on a corrupt or incomplete message, adhering to the guidance principle of rejecting oversized input explicitly rather than silently truncating it.

## Behaviour changes

- Introduced an explicit length check on the intermediate `message` buffer and now reject (return -1) if `username` concatenated with `:` and `action` would exceed 64 bytes, where the original code would silently truncate. This is a safe change because it prevents undefined behaviour rather than permitting it.
- The `snprintf` call is more efficient than the three separate operations and produces identical output for inputs that fit within the buffer.
- Return value semantics are unchanged: the function returns -1 on any failure (either buffer truncation) and 0 on success.
- Function signature and calling convention are unchanged.
