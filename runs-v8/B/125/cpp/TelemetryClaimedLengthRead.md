## Verdict

Out-of-bounds read confirmed. The function validates that `offset` is within the frame's size, but does not validate that the requested `length` does not extend past the buffer end. The loop at line 12 reads `frame[offset + i]` for `i` from 0 to `length-1` without checking that `offset + length <= frame.size()`. An attacker-supplied `length` value can cause reads beyond the allocated buffer.

## Source

```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < length; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];  // ← reads beyond buffer if length is untrusted
    }

    return checksum;
}
```

## Fix

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

The fix adds a bounds check: `offset + length > frame.size()` in the existing guard condition. This ensures that the requested range `[offset, offset + length)` is entirely within the frame buffer before entering the loop. The check is placed immediately before the read operation, as guidance specifies, and uses a clear, overflow-safe comparison (since `std::size_t` is unsigned, the condition naturally handles the boundary correctly). The fix does not change the function's return contract—it still returns 0 for invalid inputs—preserving the caller's expectations.

## Behaviour changes

- **Guarded condition**: Now returns 0 if `offset + length > frame.size()`, preventing out-of-bounds reads.
- **Loop bounds**: No longer enters the loop when the requested range exceeds the buffer, eliminating undefined behaviour.
- **Return value**: Identical for valid inputs; returns 0 for the newly-caught invalid cases instead of reading garbage memory.
