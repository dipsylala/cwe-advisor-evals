## Verdict

Confirmed. The `%s` conversion for `out->nameBuf` in the `sscanf` call has no field width, so `sscanf` will keep scanning past the end of `line`'s `LINE_CAPACITY`-byte allocation looking for a whitespace/NUL delimiter if the buffer is full of non-whitespace bytes with no terminator inside it. This is an out-of-bounds read of the `line` buffer (CWE-125), independent of the destination buffer sizes.

## Source

`line` is populated by a raw socket read (described in the header comment) that copies in exactly the number of bytes received and does not append a NUL terminator. When a peer sends `LINE_CAPACITY` (64) bytes containing no whitespace and no NUL byte, `line` is entirely full of scannable, non-delimiting data, with nothing inside its own allocation able to stop an unwidthed `%s` conversion. That untrusted, unterminated buffer flows directly into `sscanf` at line 32.

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

    /* Every %s conversion is now bounded by an explicit field width no
     * larger than LINE_CAPACITY - 1, so sscanf can never read past the
     * end of line's own allocation even when line contains no whitespace
     * or NUL byte anywhere inside it. */
    int fields = sscanf(line, "%7s %63s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);

    if (fields != 4 || strcmp(tag, "STATUS") != 0) {
        return -1;
    }

    return 0;
}
```

## Explanation

The three `%s`-family conversions in the format string are what bound how far `sscanf` is allowed to read from `line`. `%7s` and `%63s` already carry field widths, so they stop after at most 7 or 63 bytes even without a delimiter. The middle conversion, `%s` for `out->nameBuf`, had no width at all: with no width, `sscanf` keeps consuming bytes until it hits whitespace or a NUL terminator, regardless of the destination buffer's size or of `line`'s own size. Since `line` is only guaranteed to be `LINE_CAPACITY` (64) bytes and is not guaranteed to be NUL-terminated by its caller, an attacker-controlled peer that fills all 64 bytes with non-whitespace data causes the scan to run past the end of `line`'s allocation while searching for a stopping point - an out-of-bounds read.

The fix adds an explicit width, `%63s`, to that conversion. The width is chosen against `line`'s own `LINE_CAPACITY` (64), not against the size of `out->nameBuf` (256): even though `nameBuf` could hold a much longer string, `sscanf` can never legitimately consume more than `LINE_CAPACITY - 1` bytes from `line` for this field, because that's all the source buffer can ever contain. Capping the width at `LINE_CAPACITY - 1` (63) guarantees every conversion in the format string terminates within `line`'s allocation even in the worst case where the whole buffer is non-whitespace, non-NUL bytes, closing the out-of-bounds read while leaving the destination buffer size and all other behavior unchanged. `sscanf`'s return value and `tag` comparison are unaffected, since a legitimate `"STATUS <peerName> <state> <uptimeSeconds>"` line is far shorter than 64 bytes and will still match all four conversions in full.
