## Verdict
Confirmed CWE-121 stack-based buffer overflow at line 9. The `scanf("%s", code)` format string lacks a width specifier and can read unbounded input into a 16-byte fixed buffer, allowing overflow.

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
The vulnerability occurs because `scanf("%s", code)` reads an unlimited number of characters into a fixed-size 16-byte buffer. An attacker can provide input longer than 15 characters, causing the buffer to overflow.

The fix adds the width specifier `%15s` to `scanf`, which limits input to 15 characters, leaving one byte for the null terminator. This ensures the input cannot exceed the buffer's capacity of 16 bytes. The width specifier performs length validation at the input boundary rather than relying on post-read checks.
