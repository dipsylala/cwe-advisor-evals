## Verdict

Confirmed. `copy_packet_window` performs an out-of-bounds read because its bounds check can be defeated by integer overflow before the `memcpy` on line 13.

## Source

`offset` is a caller-controlled `int` parameter to `copy_packet_window`. It is not validated for sign before use.

## Fix

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

    memcpy(out, packet + uoffset, length);
    return (int)length;
}
```

## Explanation

The original guard, `(size_t)offset + length <= packet_len`, tries to bound the read window but does so with an addition that can wrap:

- `offset` is a signed `int`. If a caller passes a negative value, `(size_t)offset` does not become a small negative-looking number — it becomes a huge unsigned value near `SIZE_MAX` (two's-complement reinterpretation). For example `offset = -1` becomes `SIZE_MAX`.
- Adding `length` to that huge value overflows `size_t` and wraps back around to a small number. If that wrapped sum happens to be `<= packet_len`, the check passes even though `offset` was negative.
- `memcpy(out, packet + offset, length)` then computes `packet + offset` with the original negative `offset`, producing a pointer far outside the `packet` buffer (undefined behavior in C, and in practice a wild out-of-bounds read that is copied into `out` and returned to the caller).
- The same class of overflow can also be triggered with a large positive `offset` close to `SIZE_MAX - length`, without needing a negative value at all, on any platform where `size_t` addition can wrap.

The fix removes the overflow-prone addition entirely instead of trying to guard it:

1. Reject `offset < 0` outright, so the subsequent cast to `size_t` can never smuggle in a huge wrapped value.
2. Reject `uoffset > packet_len` before doing any arithmetic with `length`, ensuring the subtraction `packet_len - uoffset` cannot underflow.
3. Compute `remaining = packet_len - uoffset` — this is now a safe, non-overflowing subtraction because `uoffset <= packet_len` is already established — and compare `length` against it directly instead of computing a sum that could wrap.
4. Only then perform the `memcpy`, using the validated `uoffset`.

This preserves the original function's contract (returns `-1` on any invalid window, otherwise copies `length` bytes and returns it as an `int`) while making every bounds comparison overflow-safe: no step adds two potentially large values together and compares the sum, which is what allowed the original check to be bypassed.
