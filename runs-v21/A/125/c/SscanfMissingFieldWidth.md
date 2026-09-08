## Verdict
CWE-125 confirmed. The `sscanf` call on line 32 uses an unwidthed `%s` conversion specifier for `out->nameBuf`, allowing unbounded string reads to occur past the end of the 64-byte `line` buffer when searching for whitespace delimiters.

## Source
Line 32 in SscanfMissingFieldWidth.c:
```c
int fields = sscanf(line, "%7s %s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);
```

The second `%s` (for `out->nameBuf[256]`) lacks a width specifier. When the input buffer `line` has no internal whitespace or NUL terminator, `sscanf` reads past the 64-byte allocation boundary searching for a space.

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
Added width limit `%255s` for the `out->nameBuf` field. This bounds the read to 255 characters plus a NUL terminator, which fits within the 256-byte buffer allocation. With the width specifier in place, `sscanf` will stop reading either at whitespace or after 255 characters, preventing out-of-bounds reads past the end of the 64-byte `line` buffer. The other specifiers (`%7s`, `%63s`, `%d`) were already safe; only `out->nameBuf` required the fix.
