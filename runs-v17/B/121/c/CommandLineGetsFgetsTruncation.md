## Verdict

Stack-based buffer overflow via unbounded `gets()`. Remediated by replacing with `fgets()` and validating line length against buffer capacity.

## Source

The vulnerability is at line 9: `gets(line);`

`gets()` reads from stdin without a size limit and can write arbitrarily many bytes into the 64-byte stack buffer `line`, corrupting adjacent stack memory. The function was removed from the C standard library in C11 because it is inherently unsafe.

## Fix

### File: CommandLineGetsFgetsTruncation.c

```c
#include <stdio.h>
#include <string.h>

int read_command_line(char *out, size_t out_capacity)
{
    char line[64];

    // Read with size limit to prevent overflow
    if (fgets(line, sizeof line, stdin) == NULL) {
        return -1;  // EOF or error
    }

    // Check for truncation and remove newline
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
        // Complete line with newline - remove the terminator
        line[len - 1] = '\0';
        len--;
    } else if (len == sizeof line - 1) {
        // Buffer is full - check if line was actually complete
        int next_ch = getchar();
        if (next_ch != '\n' && next_ch != EOF) {
            // Line was truncated - drain the rest
            while (next_ch != '\n' && next_ch != EOF) {
                next_ch = getchar();
            }
            return -1;
        }
        // Line ended naturally at buffer boundary
    }

    // Validate against output capacity
    if (len >= out_capacity) {
        return -1;
    }
    strcpy(out, line);
    return 0;
}
```

## Explanation

The fix addresses the buffer overflow in three steps:

1. **Replace unbounded input**: `gets()` is replaced with `fgets(line, sizeof line, stdin)`, which reads at most 63 bytes (plus null terminator) into the buffer. This closes the primary overflow vector.

2. **Detect and handle truncation**: Since `fgets()` may silently truncate an over-long line, the code validates whether the complete line was read:
   - If the line ends with `\n`, it was complete; remove the newline.
   - If the buffer is full (length = 63) but has no newline, peek the next character with `getchar()`. If it is not EOF or newline, the line was truncated and we drain the rest before rejecting it.

3. **Preserve output validation**: The existing length check before copying to `out` remains in place, catching cases where the input line (now guaranteed to fit in `line`) still exceeds the caller's output buffer capacity.

This layered approach prevents both the stack overflow in `read_command_line()` and silent truncation of data that the caller would later treat as complete.

## Behaviour changes

- `gets()` is replaced with `fgets()`, preventing unbounded reads from stdin into the stack buffer.
- The function now rejects input lines longer than 63 characters (the input buffer's usable capacity), returning -1 and draining the extra input from stdin.
- Short lines are handled correctly; those that fit in both the input buffer and the output buffer are copied as before.
- The function now returns -1 on EOF or read error (previously `gets()` would store whatever partial data was present).
- Truncated lines are explicitly rejected rather than silently accepted, preventing data corruption or misinterpretation by the caller.
