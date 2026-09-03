## Verdict

Confirmed. The function performs an out-of-bounds read on line 12 when the requested length extends past the end of the frame buffer.

## Source

The `length` parameter passed to `checksumTelemetryWindow()` originates from untrusted input (the caller) and is not validated against the frame's actual size before being used in the loop bounds.

## Fix

Add bounds validation immediately after the function entry, checking both that the length fits within the buffer and that the offset plus length does not exceed the buffer size:

```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
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

The original code checked only whether `offset >= frame.size()` before entering the loop, but failed to validate that the entire range `[offset, offset + length)` remains within the buffer. When offset is valid but `offset + length` exceeds `frame.size()`, the loop reads past the end of the vector on each iteration, causing undefined behavior.

The fix adds two bounds checks executed in order:
1. First, verify `length > frame.size()` to reject oversized lengths before any subtraction
2. Then, check `offset > frame.size() - length` to confirm the offset leaves sufficient space for the requested length, using unsigned arithmetic that cannot wrap when length has been pre-validated

This pattern avoids the unsigned arithmetic pitfall where subtracting an oversized length wraps to a huge value and bypasses the guard entirely.

## Behaviour changes

The function now rejects read requests that would exceed buffer bounds by returning early with a checksum value of 0, instead of silently performing out-of-bounds reads that produce undefined behavior and potentially corrupt memory or crash the process.
