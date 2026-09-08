## Verdict

Confirmed. `copy_packet_window` accepts a signed `offset` and validates it by computing `(size_t)offset + length <= packet_len`. When `offset` is negative, the cast to `size_t` produces a very large unsigned value; adding `length` to it then wraps around (unsigned overflow) and can land back inside `[0, packet_len]`, so the bounds check passes even though the real pointer arithmetic `packet + offset` moves before the start of `packet`. The subsequent `memcpy(out, packet + offset, length)` then reads out of bounds relative to `packet`.

## Source

The tainted value is the `offset` parameter of `copy_packet_window` (an `int`, i.e. attacker/caller-controlled and permitted to be negative) as it flows unchecked into the bounds computation `(size_t)offset + length <= packet_len` and into the pointer arithmetic `packet + offset` at the `memcpy` sink on line 13.

## Fix

### File: PacketWindowUncheckedOffset.c
```c
#include <stddef.h>
#include <string.h>

int copy_packet_window(const unsigned char *packet,
                       size_t packet_len,
                       int offset,
                       size_t length,
                       unsigned char *out,
                       size_t out_capacity)
{
    if (offset < 0) {
        return -1;
    }

    size_t uoffset = (size_t)offset;

    if (uoffset > packet_len) {
        return -1;
    }

    size_t remaining = packet_len - uoffset;

    if (length > remaining || length > out_capacity) {
        return -1;
    }

    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    memcpy(out, packet + uoffset, length);
    return (int)length;
}
```

## Explanation

The original check performed the comparison in `size_t` arithmetic before validating that `offset` was non-negative. Casting a negative `int` to `size_t` yields a value near `SIZE_MAX`; adding `length` to that value overflows and wraps back into a small number that can satisfy `<= packet_len`, defeating the intended bound. Meanwhile `packet + offset` with a negative `offset` is still pointer arithmetic that steps backward from `packet`, so the `memcpy` reads memory before the start of the buffer (and, depending on the magnitude of `offset`/`length`, can read far outside it).

The fix restores validation order and removes the overflow-prone addition entirely:

1. Reject `offset < 0` up front, before any conversion to `size_t`, so a negative offset can never reach the arithmetic.
2. Convert to `size_t` only after that check, then confirm `uoffset <= packet_len` so the offset itself lies within the buffer (or exactly at its end, yielding zero remaining bytes).
3. Compute `remaining = packet_len - uoffset`. Because `uoffset <= packet_len` is already established, this subtraction cannot underflow.
4. Compare `length` against `remaining` (and separately against `out_capacity`) instead of computing `offset + length`, eliminating the unsigned-overflow path that let the original check be bypassed.

With these changes, every combination of `offset` and `length` that reaches the `memcpy` is guaranteed to describe a window fully contained within `[packet, packet + packet_len)`, and no arithmetic step can wrap around to produce a false pass. A regression test should call `copy_packet_window` with a negative `offset` (e.g. `offset = -1`, `length` and `packet_len` chosen so the old wrapped sum would have passed) and assert it returns `-1` rather than performing the copy, plus a normal in-bounds case to confirm legitimate windows still succeed.
