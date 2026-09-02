## Verdict

Confirmed. `checksumTelemetryWindow` reads past the end of `frame` whenever the caller-supplied `length` extends beyond the buffer, because only `offset` is validated against `frame.size()` and `length` is trusted as-is.

## Source

`length` (and `offset`) are parameters supplied by the caller of `checksumTelemetryWindow` and are treated as attacker/peer-controlled telemetry framing fields (a claimed window length read off the wire), not values derived from `frame.size()`.

## Fix

```cpp
#include <cstddef>
#include <cstdint>
#include <vector>

std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }

    const std::size_t available = frame.size() - offset;
    if (length > available) {
        length = available;
    }

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < length; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];
    }

    return checksum;
}
```

## Explanation

The function guards `offset` (`if (offset >= frame.size()) return 0;`) but never checks `length` against the number of bytes actually remaining in `frame` starting at `offset`. The loop `for (std::size_t i = 0; i < length; ++i)` then indexes `frame[offset + i]` using `std::vector::operator[]`, which performs no bounds checking (unlike `.at()`, which would throw `std::out_of_range`). If a caller passes a `length` larger than `frame.size() - offset` - for example a claimed telemetry payload length that does not match the actual buffer size received - the loop reads memory beyond the vector's allocated storage, producing an out-of-bounds read (CWE-125). Depending on heap layout this can leak adjacent heap memory into the computed checksum or crash the process.

The fix computes `available = frame.size() - offset` (safe because the preceding check guarantees `offset < frame.size()`, so this subtraction cannot underflow) and clamps `length` to that value before the loop runs. This makes `offset + i` always stay within `[0, frame.size())` for every iteration, eliminating the out-of-bounds access while preserving the function's behavior for all valid inputs. An equally valid alternative is to reject the call outright (e.g. return 0 or an error) when `length > available`, if silently truncating the window is not acceptable for the telemetry protocol's semantics; either way, `length` must be validated against `frame.size() - offset` before it is used to drive the read loop.
