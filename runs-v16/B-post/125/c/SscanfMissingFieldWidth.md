## Verdict

**Confirmed.** The `sscanf()` call at line 32 has two exploitable gaps:

1. The source buffer `line[64]` is not NUL-terminated (per the function comment), so `sscanf` will read past the end of the buffer looking for whitespace or a NUL terminator if none exists within those 64 bytes.
2. The second format specifier `%s` has no field width, allowing unbounded writes to `out->nameBuf[256]` if the input contains a very long token.

When a peer sends exactly 64 bytes with no whitespace or NUL anywhere in them, the `%s` conversion will scan past `line`'s allocation (CWE-125: out-of-bounds read).

## Source

The `line` parameter is a 64-byte buffer filled by a raw socket read without NUL termination. The data originates from untrusted network input. Because `sscanf()` expects a NUL-terminated C string and the function contract guarantees no terminator is present, any call to `sscanf()` on this buffer without first adding one will read past the buffer's bounds while searching for a delimiter.

## Fix

Create a NUL-terminated working copy of the input before passing it to `sscanf()`, and add a field width to every `%s` format specifier to bound the write to each destination buffer:

```c
int parsePeerStatusLine(const char line[LINE_CAPACITY], PeerStatus *out)
{
    char tag[8];
    char line_copy[LINE_CAPACITY + 1];

    memset(out, 0, sizeof(*out));

    /* Create a NUL-terminated copy to safely pass to sscanf() */
    memcpy(line_copy, line, LINE_CAPACITY);
    line_copy[LINE_CAPACITY] = '\0';

    /* Add field width to %s for nameBuf: 255 is one smaller than the 256-byte buffer */
    int fields = sscanf(line_copy, "%7s %255s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);

    if (fields != 4 || strcmp(tag, "STATUS") != 0) {
        return -1;
    }

    return 0;
}
```

## Explanation

`sscanf()` requires its input to be a NUL-terminated C string. When the input buffer is not NUL-terminated, `sscanf()` will read past its bounds while searching for whitespace or a NUL terminator to delimit the current field. The fix creates a guaranteed NUL-terminated copy of the input on the stack before passing it to `sscanf()`.

Additionally, the `%s` format without a field width is inherently unbounded and will write as many characters as needed to reach whitespace, potentially overflowing the destination buffer. Adding the field width `%255s` (one smaller than the 256-byte buffer capacity) provides defense-in-depth: if `sscanf()` somehow reads more data than expected, the write is bounded by the format specifier. Together, the NUL termination and field widths ensure both that `sscanf()` stays within the source buffer and that writes stay within destination buffers.

## Behaviour changes

- A 64-byte `line_copy` buffer is allocated on the stack to hold a NUL-terminated copy.
- Input longer than 255 characters in the `peerName` field will be truncated at 255 characters. Legitimate status lines are unlikely to exceed this, so this is an acceptable constraint that hardens the parser.
- The function now safely handles the case where the peer sends exactly 64 bytes with no whitespace or NUL terminators, instead of reading past the buffer.
