## Verdict
Out-of-bounds read confirmed. The vulnerability stems from implicit integer casting of a signed `int` offset to `size_t` in the bounds check, which allows negative offset values to wrap around to very large unsigned values and bypass the check.

## Source
```c
int copy_packet_window(const unsigned char *packet,
                       size_t packet_len,
                       int offset,
                       size_t length,
                       unsigned char *out,
                       size_t out_capacity)
{
    if ((size_t)offset + length <= packet_len && length <= out_capacity) {
        // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
        memcpy(out, packet + offset, length);
        return (int)length;
    }

    return -1;
}
```

The problematic line is:
- **Line 11**: `if ((size_t)offset + length <= packet_len && length <= out_capacity)` — The cast of signed `int offset` to `size_t` causes negative values to become very large unsigned integers, bypassing the boundary check.
- **Line 13**: `memcpy(out, packet + offset, length)` — Sink where the out-of-bounds read occurs.

## Fix
```c
int copy_packet_window(const unsigned char *packet,
                       size_t packet_len,
                       int offset,
                       size_t length,
                       unsigned char *out,
                       size_t out_capacity)
{
    // Reject negative offsets
    if (offset < 0) {
        return -1;
    }
    
    size_t uoffset = (size_t)offset;
    
    // Check if offset exceeds packet bounds
    if (uoffset > packet_len) {
        return -1;
    }
    
    // Check if length extends past packet_len from offset
    if (packet_len - uoffset < length) {
        return -1;
    }
    
    // Check destination capacity
    if (length > out_capacity) {
        return -1;
    }
    
    memcpy(out, packet + uoffset, length);
    return (int)length;
}
```

## Explanation
The vulnerability arises from casting a signed `int` to an unsigned `size_t` without first validating the sign. When `offset` is negative, the cast wraps it to a very large unsigned value, allowing the arithmetic check `(size_t)offset + length <= packet_len` to incorrectly pass even though the actual memory access would read before the beginning of the packet buffer.

The fix enforces three layers of bounds validation:

1. **Explicit negative check**: Reject any negative offset immediately before casting.
2. **Safe unsigned arithmetic**: After confirming offset is non-negative, cast it to `size_t` and perform separate checks to avoid overflow. First verify `uoffset <= packet_len`, then verify `packet_len - uoffset >= length` (subtraction-before-comparison prevents wraparound).
3. **Output capacity check**: Independently verify the destination buffer has sufficient space.

This approach eliminates the integer casting vulnerability and ensures the memcpy operation stays within both source and destination bounds.
