## Verdict

CONFIRMED

## Source

The vulnerable `sscanf` call on line 32 uses `"%7s %s %63s %d"` where the second format specifier `%s` lacks a field width limit. The input buffer `line` is exactly 64 bytes, not NUL-terminated, and can be completely filled with non-whitespace characters. The unbounded `%s` conversion will scan past the 64-byte allocation boundary looking for whitespace or a NUL terminator.

## Fix

Add a field width to the second `%s` specifier:

```c
int fields = sscanf(line, "%7s %255s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);
```

Alternatively, use a more conservative width that respects the 64-byte source buffer:

```c
int fields = sscanf(line, "%7s %63s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);
```

## Explanation

The `%s` format specifier without a field width reads characters until encountering whitespace or a NUL terminator. When the input buffer is full of non-whitespace content with no internal NUL terminator, the scan continues indefinitely past the buffer boundary. Adding a field width (e.g., `%255s` for the 256-byte `nameBuf`, or `%63s` to stay within the 64-byte source) constrains the read to a safe maximum, preventing the out-of-bounds read from adjacent memory.
