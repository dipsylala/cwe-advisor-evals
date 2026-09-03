## Verdict

True positive. The code performs an unchecked out-of-bounds read when the caller supplies a `length` parameter that extends beyond the vector's bounds.

## Source

```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < length; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];  // Line 12: out-of-bounds read
    }

    return checksum;
}
```

## Fix

```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }

    // Clamp length to ensure offset + length does not exceed frame.size()
    std::size_t available = frame.size() - offset;
    std::size_t effectiveLength = (length < available) ? length : available;

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < effectiveLength; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];
    }

    return checksum;
}
```

## Explanation

The vulnerability arises because the initial bounds check only verifies that `offset` is within range, but the loop then reads `length` elements starting at `offset` without validating that `offset + length` stays within the vector's bounds.

The fix calculates the available space from `offset` to the end of the vector, then clamps the requested `length` to that available space. This ensures every array access in the loop stays within bounds. If the caller requests more data than available, the function processes only the available data and returns a checksum computed over that prefix.

This approach preserves the function's contract—it returns early if the starting offset is invalid—while preventing out-of-bounds reads when the requested window extends past the vector's end.
