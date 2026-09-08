## Verdict

Confirmed. `checksumTelemetryWindow` reads out of bounds when the caller-supplied `length` (a claimed length, not a verified one) extends past the end of `frame`.

## Source

`length` (and `offset`) are parameters passed in by the caller and are treated as a trusted description of how many bytes are available starting at `offset`, with no relationship enforced to the actual size of `frame`.

## Fix

### File: TelemetryClaimedLengthRead.cpp
```cpp
#include <cstddef>
#include <cstdint>
#include <vector>

std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }

    const std::size_t available = frame.size() - offset;
    const std::size_t bytesToRead = length < available ? length : available;

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < bytesToRead; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];
    }

    return checksum;
}
```

## Explanation

The original code only checks `offset >= frame.size()` and then loops `length` times reading `frame[offset + i]`. Nothing ties `length` to the actual remaining size of `frame`, so any caller that passes a `length` larger than `frame.size() - offset` (for example, a length taken from a telemetry packet's header field rather than derived from the buffer itself) causes the loop to index past the end of the underlying `std::vector`, which is undefined behavior and an out-of-bounds read (CWE-125).

The fix computes `available`, the number of bytes actually remaining in `frame` from `offset` onward (safe from underflow because the preceding check guarantees `offset < frame.size()`), and clamps the number of bytes read to `min(length, available)`. This preserves the function's intended behavior for any valid, in-range window - the checksum is unchanged whenever the caller's claimed length was already correct - while a claimed length that overruns the buffer is silently truncated to the bytes that actually exist instead of reading adjacent memory. No caller-visible contract changes for well-formed input; only the previously-unsafe case is affected.
