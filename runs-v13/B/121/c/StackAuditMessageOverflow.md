## Verdict

Confirmed. Lines 11 and 14 use `strcpy` and `strcat` without validating the lengths of `username` and `action` against the 64-byte `message` buffer. An attacker controlling either input can overflow the stack buffer.

## Source

The vulnerable pattern is unbounded string concatenation into a fixed-size stack buffer:

```c
char message[64];

strcpy(message, username);      // No length check on username
strcat(message, ":");
strcat(message, action);        // No length check on action
```

The function accepts `username` and `action` as untrusted input from the caller but writes them into the local `message` array without first verifying that their combined length fits within 64 bytes. If either input is long, the write spills past the buffer boundary, corrupting the return address and enabling code execution.

## Fix

Replace the unbounded `strcpy` and `strcat` calls with a single `snprintf` that enforces the destination buffer's capacity:

```c
#include <stdio.h>
#include <string.h>

int build_audit_message(const char *username,
                        const char *action,
                        char *out,
                        size_t out_capacity)
{
    char message[64];

    // Use snprintf to safely format the message, bounded by buffer size
    int result = snprintf(message, sizeof(message), "%s:%s", username, action);
    if (result < 0 || (size_t)result >= sizeof(message)) {
        return -1;  // Input too large or encoding error
    }

    int written = snprintf(out, out_capacity, "AUDIT %s", message);
    if (written < 0 || (size_t)written >= out_capacity) {
        return -1;
    }
    return 0;
}
```

## Explanation

The fix replaces three unbounded operations (`strcpy`, `strcat`, `strcat`) with a single `snprintf` call that:

1. Takes an explicit destination size argument (`sizeof(message)`)
2. Formats the template string `"%s:%s"` with the inputs `username` and `action`, applying bounds checking to the concatenation
3. Returns the length that would have been written; if that length is >= the buffer size, the input was too large and truncation occurred

The check `(size_t)result >= sizeof(message)` detects truncation and rejects the oversized input rather than silently truncating and proceeding. This prevents the buffer overflow and avoids passing a corrupted audit message downstream.

`snprintf` is the standard C mechanism for bounded string formatting and is safer than a manual sequence of `strcpy`/`strcat` calls because both the source and destination bounds are applied in a single operation, reducing the risk of an intermediate state (after `strcpy` but before the final `strcat`) overflowing.

## Behaviour changes

- **Input validation**: Inputs that would cause truncation in the `message` buffer are now rejected (return value -1) rather than silently truncated.
- **Security**: Stack memory after the `message` buffer is no longer corrupted by oversized `username` or `action` values.
- **Error handling**: Callers must now check the return value; a -1 response signals that the input was too large for the audit message buffer.
- **Audit trail**: Audit messages that cannot fit in 64 bytes are rejected entirely, preventing a partial or corrupted record from being logged.
