## Verdict

Out-of-bounds write confirmed. The bounds check at line 6 validates only the payload length against capacity, but does not account for the offset parameter. An attacker can supply a large offset combined with a length that, when summed, exceeds the destination buffer's capacity, causing `memcpy` to write past the allocated region.

## Source

The vulnerable function `write_payload` at line 10 in `buffer_writer.c`:

```
memcpy(destination + offset, payload, length);
```

The preceding check (line 6–7) is insufficient:

```
if (length > capacity) {
    return;
}
```

This check does not verify that `offset + length` remains within bounds. When `offset` is large, the write extends past the buffer end even if `length` alone would fit.

## Fix

Replace the bounds check with:

```c
if (offset + length > capacity) {
    return;
}
```

This ensures that the combination of offset and length does not exceed the destination buffer's capacity, preventing out-of-bounds writes regardless of the offset value.

## Explanation

The original check compares only the payload length to the capacity, ignoring that the write starts at a non-zero offset within the buffer. When `memcpy(destination + offset, payload, length)` executes, the bytes written span from `offset` to `offset + length - 1`. The capacity constraint must enforce that `offset + length <= capacity` to keep the entire write region within the allocated buffer. The fix corrects this by adding the offset into the bounds calculation, ensuring the write does not escape the buffer regardless of how the offset and length are chosen.
