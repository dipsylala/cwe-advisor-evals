## Verdict
Stack-based buffer overflow confirmed at line 14. The unsafe `strcpy` and `strcat` functions lack bounds checking, allowing `username` and `action` to overflow the fixed 64-byte `message` buffer if their combined length exceeds capacity.

## Source
```c
char message[64];

strcpy(message, username);          // Line 11: No bounds check
strcat(message, ":");               // Line 12: No bounds check
strcat(message, action);            // Line 14: Buffer overflow sink
```

The `message` buffer is statically sized at 64 bytes. If `username` is sufficiently long (e.g., 50+ bytes), or if `action` is long, the concatenation exceeds the buffer and overwrites adjacent stack memory.

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
Replaced the unsafe `strcpy`/`strcat` sequence with a single `snprintf` call to safely format `username:action` into the `message` buffer. The `snprintf` function enforces the buffer size constraint (`sizeof(message)` = 64 bytes), truncating if necessary and returning the number of characters that would have been written. The check `if (written < 0 || (size_t)written >= sizeof(message))` detects both errors and truncation, preventing buffer overflow and ensuring the function rejects oversized input rather than corrupting the stack. This pattern mirrors the existing bounds check on the output buffer, applying the same defensive discipline to the intermediate construction.
