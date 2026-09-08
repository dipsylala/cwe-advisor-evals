## Verdict

Exploitable

## Source

Function parameter `line` (from network socket, filled by raw socket read without NUL terminator)

## Fix

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

    memset(out, 0, sizeof(*out));

    /* SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement. */
    int fields = sscanf(line, "%7s %255s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);

    if (fields != 4 || strcmp(tag, "STATUS") != 0) {
        return -1;
    }

    return 0;
}
```

## Explanation

The vulnerability occurs because the `sscanf()` format string contains an unwidthed `%s` conversion that reads into `out->nameBuf`. When the input buffer `line` is completely filled (64 bytes) with non-whitespace characters and contains no NUL terminator (as documented in the function's comment), the `%s` conversion has no in-buffer delimiter to stop it and continues reading past the 64-byte allocation boundary, causing an out-of-bounds read. The fix adds an explicit field width (`%255s`) to the second format specifier, constraining the read to 255 characters (leaving 1 byte for the NUL terminator that `sscanf()` appends to the `256`-byte destination buffer). This prevents the scan from running past the input buffer's boundary. Per the C-specific guidance, a literal field width one smaller than the destination buffer size is the correct pattern for `sscanf()` when the source is not guaranteed to be NUL-terminated.

## Behaviour changes

None. The format string change constrains an unbounded read to its safe limit (255 characters into a 256-byte buffer) without altering the return value, error handling, or the data successfully parsed on valid input. The `sscanf()` return value and comparison logic remain unchanged.
