## Verdict

Exploitable. Confidence: high.

CWE-121 (Stack-based Buffer Overflow) confirmed at `TicketCodeScanfWidthOffByOne.c:9`. `scanf("%s", code)` reads into `char code[16]` with no field-width limit, so any input token of 16 or more characters writes past the end of the buffer, corrupting adjacent stack memory.

## Source

- **Source**: stdin, read by `scanf("%s", code)` in `read_ticket_code`. `%s` has no bound of its own - it reads and writes characters until the next whitespace or EOF, regardless of the destination's size.
- **Sink**: the same `scanf("%s", code)` call (line 9). `code` is declared `char code[16]`, an 16-byte fixed stack array; the call has no field-width specifier, so an attacker-controlled token of 16+ characters overflows it before the function ever reaches the existing `strlen(code) >= out_capacity` check further down - that check runs after the overflow has already happened, so it cannot prevent it.
- Sink contract: `scanf` returns the count of successfully matched/assigned items (checked against `1`); on match it null-terminates `code` and leaves any trailing whitespace delimiter unread on the stream; on no match it leaves `code` untouched and the offending characters unread. Nothing downstream inspects the stream position, so preserving it is only needed to keep repeated calls to `read_ticket_code` (or other stdin readers) working the same way as before.

## Fix

### File: TicketCodeScanfWidthOffByOne.c

```c
#include <ctype.h>
#include <stdio.h>
#include <string.h>

int read_ticket_code(char *out, size_t out_capacity)
{
    char code[16];

    if (scanf("%15s", code) != 1) {
        return -1;
    }

    /* "%15s" stops after 15 characters even if the token is longer, so a
     * code longer than the buffer can hold is silently split rather than
     * overflowing. Peek the next character: if it is not whitespace or
     * EOF, the rest of the same token is still queued on stdin, which
     * means `code` holds a truncated fragment, not the real value - drain
     * the remainder and reject instead of accepting the fragment. */
    int next = getchar();
    if (next != EOF && !isspace(next)) {
        while (next != EOF && !isspace(next)) {
            next = getchar();
        }
        return -1;
    }
    if (next != EOF) {
        ungetc(next, stdin);
    }

    if (strlen(code) >= out_capacity) {
        return -1;
    }
    strcpy(out, code);
    return 0;
}
```

## Explanation

The overflow comes from `scanf("%s", code)` having no field-width limit, so it will write as many characters as the input token contains regardless of `code`'s 16-byte capacity. The fix adds an explicit width specifier, `%15s`, sized as the buffer's declared capacity minus one byte reserved for the NUL terminator that `scanf` always appends - closing the out-of-bounds write. A width limit alone would silently truncate an over-long code to 15 characters and treat the fragment as valid, which is a different value than what was entered, so the fix also peeks the next character on the stream with `getchar()`: if it is not whitespace or `EOF`, the token was longer than 15 characters and got cut off, so the remainder is drained and the call is rejected rather than accepting the truncated fragment. When the token was not truncated, the peeked character (the normal trailing delimiter, or `EOF`) is pushed back with `ungetc` so the stream is left exactly as `scanf("%s", ...)` would have left it, preserving the existing sink contract for any caller that reads from stdin afterward. The pre-existing `strlen(code) >= out_capacity` check and `strcpy(out, code)` are unchanged, since the buffer overflow was in the `scanf` call, not in that later copy.

## Behaviour changes

- **Oversized input now rejected instead of overflowing**: a code of 16+ characters previously overflowed the stack buffer (undefined behaviour). It now returns `-1` and the excess characters are drained from stdin. This is the fix itself, not incidental.
- **Trailing delimiter handling**: on a successful read, one character is peeked from stdin via `getchar()` and immediately pushed back with `ungetc` if it isn't consumed as part of rejecting a truncated token. Net effect on the stream position is unchanged from the original `scanf("%s", ...)` behaviour for all non-overflowing inputs.
- **New includes**: `<ctype.h>` added for `isspace`, a C standard library function, needed to detect the whitespace/EOF boundary used to distinguish a complete token from a truncated one.
- Everything else - the `strlen(code) >= out_capacity` check, `strcpy(out, code)`, the function signature, and the `-1`/`0` return convention - is unchanged.

## Verification

No C compiler was reachable in this environment (`gcc`/`cc` not found on `PATH`). Reviewed by hand instead: `scanf`, `getchar`, `isspace`, `ungetc`, `strlen`, and `strcpy` are all C standard library functions declared by the headers included (`stdio.h`, `ctype.h`, `string.h`); `ungetc(int c, FILE *stream)` and `isspace(int)` are called with argument types matching their prototypes (`getchar()`'s `int` result, which is always representable as `unsigned char` or `EOF`); the function signature, parameter list, and both return paths (`0` and `-1`) are unchanged from the original, so no caller needs updating.

## Assumptions

- The finding's "sink is the next statement" note (line 8 comment, line 9 code) was read as pointing at the `scanf` call itself, since that is the only write into `code` and the field-width omission is the entire weakness - confirmed by the case name (`ScanfWidthOffByOne`), which specifically flags the field-width value as the point under test.
- Field width was set to `15` (buffer size 16 minus 1 for the NUL terminator `scanf` appends), per the CWE-121/c guidance's "reserve room for a terminator" and "check the new bound carefully... off by one" principles.
