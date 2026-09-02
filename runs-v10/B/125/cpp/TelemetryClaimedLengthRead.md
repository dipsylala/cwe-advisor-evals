## Verdict
exploitable

## Source
The `offset` and `length` parameters to `checksumTelemetryWindow` are untrusted input that drive the range of the buffer read.

## Fix

**Vulnerable code:**
```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < length; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];  // Out-of-bounds read when offset + length > frame.size()
    }

    return checksum;
}
```

**Fixed code:**
```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size() || offset + length > frame.size()) {
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
The original code checks only that `offset` is within bounds, but does not validate that the requested range `[offset, offset + length)` stays within the buffer. If a caller supplies `offset=5, length=10` to a 10-element vector, the check passes but the loop reads from indices 5 through 14, exceeding the buffer. The fix adds an explicit bounds check for the upper bound of the requested range before the loop. The condition `offset + length > frame.size()` ensures the entire range is valid; since all values are `std::size_t` (unsigned), the addition cannot wrap below zero. On invalid input, the function returns 0, matching its existing error-handling pattern.

## Behaviour changes
none
