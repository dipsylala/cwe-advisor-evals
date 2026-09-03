## Verdict

**VULNERABLE**. The bounds check casts the signed `offset` to `size_t` within the comparison expression, allowing negative offsets to wrap to `SIZE_MAX` and bypass the bounds check. Example: `offset = -1` becomes `SIZE_MAX` after cast, and `SIZE_MAX + 1 <= packet_len` wraps back to `0 + 1 <= packet_len`, passing even for small buffers, then `packet + (-1)` reads before the buffer.

## Source

- **Parameter**: `offset` (signed `int`)
- **Flow**: Passed directly to pointer arithmetic `packet + offset` without prior sign validation
- **Sink**: `memcpy(out, packet + offset, length)` at line 13

## Fix

Replace line 11 with:

```c
if (offset >= 0 && (size_t)offset <= packet_len && length <= packet_len - (size_t)offset && length <= out_capacity) {
```

Explanation of the check order:
1. `offset >= 0` — validate sign while the value is still signed; rejects negative offsets before any conversion
2. `(size_t)offset <= packet_len` — ensure offset alone does not exceed buffer size
3. `length <= packet_len - (size_t)offset` — ensure length from that offset does not overflow; subtraction in this order prevents underflow
4. `length <= out_capacity` — validate destination capacity (unchanged)

## Explanation

The original bounds check `(size_t)offset + length <= packet_len` performs the conversion from `int` to `size_t` inside the comparison. When `offset` is negative, the cast produces `SIZE_MAX` or nearby large values. Adding `length` to `SIZE_MAX` wraps the sum back into the range `[0, SIZE_MAX)`, causing a small length to appear to pass the bounds check even though the actual read will occur far outside the buffer.

The fixed pattern validates the sign of `offset` in its original `int` form before any unsigned cast. After confirming `offset >= 0`, the subtraction `packet_len - (size_t)offset` is safe because `offset` has been proven non-negative and smaller than `packet_len`. This eliminates the wraparound window.

The fix also reorders the checks to match the C guidance principle: validate the offset alone first, then the length against the remaining capacity from that offset. This prevents both underflow in the subtraction and oversized lengths from slipping through.

## Behaviour changes

- Calls with negative `offset` now return `-1` (error) instead of reading out-of-bounds.
- Calls with `offset >= 0` and valid `offset + length <= packet_len` proceed as before.
- No change to return values, output format, or success cases; the function rejects only previously-exploitable invalid inputs.
