## Verdict

Real issue. The vulnerability is confirmed: `scanf("%s", code)` on line 9 reads an unbounded string into a 16-byte stack buffer without any length constraint, permitting a stack-based buffer overflow.

## Source

```c
#include <stdio.h>
#include <string.h>

int read_ticket_code(char *out, size_t out_capacity)
{
    char code[16];

    // SAST FINDING: CWE-121 (Stack-based Buffer Overflow) reported here. Sink is the next statement.
    if (scanf("%s", code) != 1) {
        return -1;
    }

    if (strlen(code) >= out_capacity) {
        return -1;
    }
    strcpy(out, code);
    return 0;
}
```

## Fix

```c
#include <stdio.h>
#include <string.h>

int read_ticket_code(char *out, size_t out_capacity)
{
    char code[16];

    // SAST FINDING: CWE-121 (Stack-based Buffer Overflow) reported here. Sink is the next statement.
    if (scanf("%15s", code) != 1) {
        return -1;
    }

    if (strlen(code) >= out_capacity) {
        return -1;
    }
    strcpy(out, code);
    return 0;
}
```

## Explanation

The vulnerability occurs because `scanf("%s", code)` reads an arbitrary-length string into a 16-byte buffer with no input length limit. An attacker can supply input longer than 15 characters, causing the format specifier to write past the buffer boundary and corrupt the stack.

The fix adds a width specifier to the format string: `"%15s"` instead of `"%s"`. This constrains `scanf` to read at most 15 characters (plus the null terminator that `%s` automatically appends), which fits safely within the 16-byte buffer. The width limit prevents unbounded input from overflowing the stack.

This is the standard defense against format string overflows in C: always specify a maximum width when using `%s` in `scanf`, `fscanf`, or similar functions. The width must be strictly less than the buffer size to leave room for the null terminator.
