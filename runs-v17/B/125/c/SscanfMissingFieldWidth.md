## Verdict

The vulnerability is **confirmed and exploitable**. The finding accurately identifies a classic out-of-bounds read in `sscanf()` parsing of an unterminated buffer.

## Source

The attacker-controlled source is the `line` parameter: a 64-byte fixed-size buffer filled from a raw socket read without NUL termination. The vulnerability comment states this explicitly: "a peer that sends LINE_CAPACITY bytes with no whitespace or NUL anywhere in them leaves the buffer completely full of scannable data with nothing inside its allocation to stop sscanf's %s conversion."

## Fix

The source buffer must be NUL-terminated before `sscanf()` attempts to scan it. Additionally, all format specifiers must use explicit field widths to bound writes to destination buffers. The complete fixed function is:

### File: SscanfMissingFieldWidth.c

```c
#include <stdio.h>
#include <string.h>

#define LINE_CAPACITY 64

/*
 * Parses a fixed-format peer status line of the form:
 *   "STATUS <peerName> <state> <uptimeSeconds>"
 * The line buffer is filled by a raw socket read that copies in exactly
 * the number of bytes actually received and does not append a NUL
 * terminator, so a peer that sends LINE_CAPACITY bytes with no whitespace
 * or NUL anywhere in them leaves the buffer completely full of scannable
 * data with nothing inside its allocation to stop sscanf's %s conversion.
 * The destination fields are deliberately larger than any legitimate
 * value, so the write side is not the limiting factor here - the bug is
 * that the unwidthed %s has to keep reading line looking for a delimiter,
 * and can run past line's own LINE_CAPACITY-byte allocation to find one.
 */
typedef struct {
    char nameBuf[256];
    char state[64];
    int uptimeSeconds;
} PeerStatus;

int parsePeerStatusLine(const char line[LINE_CAPACITY], PeerStatus *out)
{
    char tag[8];
    char lineCopy[LINE_CAPACITY + 1];

    memset(out, 0, sizeof(*out));

    /* Create a NUL-terminated copy of the input buffer to prevent sscanf
     * from reading past the LINE_CAPACITY-byte allocation. */
    memcpy(lineCopy, line, LINE_CAPACITY);
    lineCopy[LINE_CAPACITY] = '\0';

    /* Use field widths for all conversion specifiers: %7s for tag (7 + 1 null
     * for 8-byte buffer), %255s for nameBuf (255 + 1 null for 256-byte buffer),
     * and %63s for state (63 + 1 null for 64-byte buffer). Scan lineCopy
     * instead of line so sscanf can rely on the NUL terminator. */
    int fields = sscanf(lineCopy, "%7s %255s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);

    if (fields != 4 || strcmp(tag, "STATUS") != 0) {
        return -1;
    }

    return 0;
}
```

## Explanation

The fix addresses CWE-125 by ensuring `sscanf()` reads from a properly NUL-terminated buffer:

1. **NUL termination**: A temporary 65-byte stack buffer `lineCopy` receives a copy of the 64-byte source via `memcpy()`, then is explicitly NUL-terminated at `lineCopy[64]`. This guarantees that `sscanf()` will find a terminator within the allocated region when parsing the unwidthed `%s` fields.

2. **Field widths**: The format string is updated from `"%7s %s %63s %d"` to `"%7s %255s %63s %d"`, adding the missing field width to the second `%s`. This prevents `out->nameBuf` from receiving more than 255 characters (plus the NUL terminator, totalling 256 bytes), matching its declared size.

3. **Sink switch**: `sscanf()` now scans `lineCopy` (the NUL-terminated copy) rather than `line` (the unterminated source). The NUL terminator in `lineCopy` stops all string conversions within its allocated region, eliminating the out-of-bounds read.

The fix matches the guidance in `cwe/125/c/INDEX.md`: "Write a literal width one smaller than the destination (`%99s` for a `char[100]`), and confirm the source is NUL-terminated inside its own allocation before scanning it."

## Behaviour changes

The function's observable behaviour does not change for valid inputs:

- **Valid case**: When the input line is a complete valid record (e.g., "STATUS peer01 up 12345"), `lineCopy` receives the same data (with padding), the NUL terminator stops parsing at exactly the same boundaries, and `sscanf()` returns the same result.

- **Invalid/malformed case**: When the input is truncated or missing fields, `lineCopy` is still properly scanned with field width limits, and `sscanf()` returns the same field count (likely less than 4, triggering the error check on line 34).

The only change is internal: the scan now operates on a bounded, terminated buffer instead of an unbounded, unterminated one. The return value and error handling remain identical. No logic is altered; only the safety contract of the scan is restored.
