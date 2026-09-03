## Verdict

Exploitable

## Source

The `length` parameter supplied by the caller, traced to the loop iteration count on line 12.

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
    if (offset >= frame.size()) {
        return 0;
    }

    // Validate that offset + length does not exceed buffer bounds
    if (offset > frame.size() - length) {
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

The vulnerability occurs because the function validates the `offset` parameter against the buffer size but fails to validate that the claimed `length` does not extend the read past the buffer's end. When the loop executes, the expression `offset + i` can exceed `frame.size()`, causing an out-of-bounds read via `operator[]`. The fix adds an explicit bounds check before the loop to ensure that `offset + length` cannot exceed the buffer size. The check uses saturating comparison (`offset > frame.size() - length`) to prevent integer underflow, and returns 0 (consistent with the existing `offset >= frame.size()` path) when validation fails. This eliminates the out-of-bounds read by ensuring all accesses within the loop stay within the allocated buffer.

## Behaviour changes

The function now returns 0 if the claimed `length` extends past the buffer boundary, whereas previously it would have performed an out-of-bounds read. This changes the outcome only when the caller supplies a `length` that exceeds available data; callers providing valid lengths see no change in behaviour.
