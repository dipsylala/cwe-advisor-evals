## Verdict

Confirmed. `scanf("%s", code)` reads into the fixed-size stack buffer `char code[16]` with no field-width limit, so any input of 16 or more characters (plus the terminating NUL `scanf` appends) overflows `code` before the subsequent `strlen`/capacity check ever runs. The capacity check on line 13 only bounds the copy into the caller's `out` buffer; it does nothing to protect `code` itself, since the overflow already happened during the `scanf` call on line 9.

## Source

`scanf("%s", code)` at line 9 in `read_ticket_code()` — `code` is attacker-controlled input read directly from standard input with an unbounded `%s` conversion.

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

`code` is a 16-byte stack array, but `%s` in `scanf` has no implicit bound — it will keep writing characters (plus a terminating NUL) for as long as input is available, corrupting adjacent stack memory (saved registers, the return address, or other locals) once the input reaches or exceeds 16 bytes. The fix adds an explicit maximum field width, `%15s`, which caps `scanf` at writing 15 data bytes into `code` and then appending the NUL terminator itself, for a maximum write of 16 bytes total — exactly the size of the buffer. The width must be one less than the array size to leave room for the terminator; using `%16s` here would still overflow by one byte.

This does not change the function's later logic: `strlen(code)` and the `out_capacity` check still validate the (now safely bounded) string before it is copied into the caller-supplied buffer with `strcpy`. Overlong ticket codes are truncated to 15 characters by `scanf` rather than corrupting the stack, and codes that still don't fit `out_capacity` continue to be rejected by the existing check.

To verify: with the original code, feeding `read_ticket_code` more than 15 characters of standard input (e.g. via a harness or fuzzer) corrupts memory beyond `code` — observable under AddressSanitizer as a stack-buffer-overflow, or as a crash/undefined behavior in an unsanitized build. After the fix, the same input is safely truncated to 15 characters plus a NUL terminator, `code` never overflows, and ASan/valgrind report no out-of-bounds write regardless of input length.
