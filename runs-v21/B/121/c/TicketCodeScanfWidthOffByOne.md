## Verdict

Exploitable

## Source

User input from stdin via `scanf()`

## Sink

`scanf("%s", code)` at line 9 reads an unbounded string into a 16-byte stack buffer without a size limit.

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

The vulnerability is a stack buffer overflow caused by `scanf("%s", code)` reading an unbounded string from stdin into a 16-byte stack-allocated buffer. An attacker can provide input longer than 15 characters, corrupting the stack and potentially enabling code execution. The fix adds a width specifier to the format string, changing `"%s"` to `"%15s"`, which instructs scanf to read at most 15 characters plus the null terminator, exactly filling the 16-byte buffer without overflow. The width limit is sized to the destination buffer's actual declared capacity minus one byte for the null terminator.

## Behaviour changes

Input longer than 15 characters is now truncated by scanf; the remaining characters remain in the input stream and can be read by subsequent operations. The rest of the function's contract remains intact: the return value on success is still 0, the error handling on scanf failure is unchanged, and the subsequent length validation still applies to the resulting code string.
