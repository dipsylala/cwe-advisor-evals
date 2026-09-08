## Verdict
Real vulnerability. The function performs an out-of-bounds read on line 12 when the caller supplies a `length` that, combined with `offset`, exceeds the vector's bounds. The existing check `if (offset >= frame.size())` validates only the starting index and does not prevent reading past the end of the buffer.

## Source
The vulnerable data flow originates from the function's parameters `offset` and `length`, both attacker-controlled. The function reads from `frame[offset + i]` without validating that `offset + length` stays within `frame.size()`.

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

    if (length > frame.size() || offset > frame.size() - length) {
        return 0;
    }

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < length; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];
    }

    return checksum;
}
```

## Explanation
The fix adds a second bounds check immediately before the loop that computes the safe upper bound. The check follows the pattern from CWE-125 C++ guidance: `length > frame.size() || offset > frame.size() - length`, tested in that order. Testing `length > frame.size()` first prevents unsigned integer underflow in the subtraction `frame.size() - length`. After both checks pass, `offset + i` for all `i` in `[0, length)` is guaranteed to stay within `[0, frame.size())`. The function returns 0 when the requested range is invalid, preserving the original contract for the offset-out-of-bounds case.

## Behaviour changes
The function now rejects requests where `offset + length` exceeds the buffer. Previously, such requests caused undefined behaviour (out-of-bounds read). Callers attempting to read past the end now receive a return value of 0 instead of undefined data. This is a correctness fix with no impact on correct usage patterns.
