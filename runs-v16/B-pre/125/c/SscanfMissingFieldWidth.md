## Verdict

Real issue, confirmed as exploitable. The second `%s` conversion in the `sscanf()` call has no field width, and the source buffer `line` is not NUL-terminated. If `line` is completely filled with non-whitespace bytes (64 bytes) with no delimiter, `sscanf` will read past the buffer boundary searching for whitespace to terminate the field.

## Source

File: `evals/cases/125/c/SscanfMissingFieldWidth/SscanfMissingFieldWidth.c`, line 32

The `parsePeerStatusLine()` function receives a 64-byte buffer `line` filled by a raw socket read that does not append a NUL terminator. The format string `"%7s %s %63s %d"` attempts to scan four fields, but the second `%s` for `nameBuf` carries no field width, and the source buffer is not guaranteed to be NUL-terminated within its allocation.

```c
int fields = sscanf(line, "%7s %s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);
```

An attacker can craft input that fills all 64 bytes of `line` with non-whitespace characters and no NUL terminator. The `sscanf()` conversion will scan past the end of the buffer searching for a whitespace delimiter.

## Fix

Add two defences:

1. **Validate source buffer**: Use `strnlen()` to confirm `line` contains a NUL terminator within its 64-byte allocation before calling `sscanf()`. Reject input that lacks it.

2. **Add field width**: Constrain the second `%s` to a literal width one smaller than its destination (`nameBuf[256]` → `%255s`) to prevent a buffer overflow on the destination side if the source is later shortened or modified.

```c
int parsePeerStatusLine(const char line[LINE_CAPACITY], PeerStatus *out)
{
    char tag[8];

    memset(out, 0, sizeof(*out));

    /* Verify source buffer is NUL-terminated within its allocation before scanning */
    if (strnlen(line, LINE_CAPACITY) == LINE_CAPACITY) {
        /* No NUL terminator found within the buffer; reject unterminated input */
        return -1;
    }

    /* Add field width to second %s to limit read to destination size */
    int fields = sscanf(line, "%7s %255s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);

    if (fields != 4 || strcmp(tag, "STATUS") != 0) {
        return -1;
    }

    return 0;
}
```

## Explanation

The `strnlen(line, LINE_CAPACITY)` call verifies that the source buffer contains a NUL terminator within its allocated size. If it returns `LINE_CAPACITY`, no terminator was found within the first 64 bytes, indicating the buffer was filled to capacity with no delimiter; the function rejects this input. If it returns a value less than `LINE_CAPACITY`, the NUL is present at position `[length]` and the buffer is safe to scan.

The field width `%255s` on the second conversion limits `sscanf()` to read at most 255 characters from the source and store them in `nameBuf[256]` (leaving room for the NUL terminator). Combined with the NUL-termination check on the source, this ensures the `sscanf()` call stays within bounds on both the source and destination sides.

## Behaviour changes

- The function now rejects input where `line` is not NUL-terminated within its 64-byte allocation and returns -1 instead of attempting the scan. This is necessary and correct, because the function cannot safely parse a buffer that lacks a terminator within its known bounds.
- The second `%s` field is now bounded to 255 characters, which is safe given that `nameBuf` is 256 bytes.
