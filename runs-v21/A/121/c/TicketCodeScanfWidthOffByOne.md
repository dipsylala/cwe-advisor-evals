## Verdict

VULNERABLE: Stack-based buffer overflow on line 9. The `scanf("%s", code)` call reads an unbounded string into a 16-byte buffer, allowing input longer than 15 characters to overflow the stack.

## Source

Line 9 in TicketCodeScanfWidthOffByOne.c:
```c
if (scanf("%s", code) != 1) {
```

The `code` buffer is declared with fixed size 16 bytes (line 6), but `scanf` with the `%s` format specifier has no width limit, so it reads until whitespace is encountered, regardless of buffer size.

## Fix

### File: TicketCodeScanfWidthOffByOne.c

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

The vulnerability exists because `scanf("%s", code)` reads without bounds into a 16-byte buffer. An attacker can input a string longer than 15 characters, overwriting the stack.

The fix adds a width specifier `%15s` to the format string, limiting `scanf` to read at most 15 characters into the 16-byte buffer, leaving space for the null terminator. This ensures the buffer cannot overflow from user input.
