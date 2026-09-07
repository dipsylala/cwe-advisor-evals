## Verdict
exploitable

## Source
stdin (user input via `fgets`/`scanf`)

## Fix

### File: TicketCodeScanfWidthOffByOne.c

```c
#include <stdio.h>
#include <string.h>

int read_ticket_code(char *out, size_t out_capacity)
{
    char code[16];

    // Use fgets with size limit to prevent buffer overflow
    if (fgets(code, sizeof(code), stdin) == NULL) {
        return -1;
    }

    // Check if the entire line was read
    size_t len = strlen(code);
    if (len > 0 && code[len - 1] == '\n') {
        // Remove the trailing newline
        code[len - 1] = '\0';
    } else if (len == sizeof(code) - 1) {
        // Buffer is full without a trailing newline - check if there's more input
        int c = getchar();
        if (c != '\n' && c != EOF) {
            // Input was truncated - drain the rest
            while ((c = getchar()) != '\n' && c != EOF)
                ;
            return -1;
        }
        // Otherwise, the input was exactly sizeof(code)-1 chars, which is OK
    }

    if (strlen(code) >= out_capacity) {
        return -1;
    }
    strcpy(out, code);
    return 0;
}
```

## Explanation

The original code used `scanf("%s", code)` to read user input into a 16-byte stack buffer. The `%s` format specifier reads an unbounded string until whitespace, with no size limit, causing a stack-based buffer overflow when the input exceeds the buffer capacity. The fix replaces `scanf` with `fgets(code, sizeof(code), stdin)`, which reads at most 15 characters (one less than the buffer size) to reserve space for the null terminator. Additionally, the fix validates that the entire input line was read: if the buffer fills without encountering a newline, it peeks the next character with `getchar()` to distinguish between a legitimate 15-character input (followed by EOF or newline) and truncation. On truncation, the remainder of the input is drained and the function returns -1 to explicitly reject oversized input rather than silently accepting a truncated value.

## Behaviour changes

1. **Input validation now rejects truncation**: The original code silently accepted input longer than the buffer by truncating it. The fixed code explicitly rejects input longer than 15 characters by draining the excess and returning -1. This is intentional per CWE-121 guidance to "reject oversized input explicitly rather than silently truncating it."

2. **Newline handling**: The original code would include the newline in the buffer if present. The fixed code removes the trailing newline before further processing, as is standard for line input. This simplifies the downstream logic since `code` now contains only the actual input, not the line terminator.

3. **No other behaviour changes**: The output buffer validation (checking against `out_capacity`) and the final `strcpy` remain unchanged. Return values (-1 on error, 0 on success) are preserved.
