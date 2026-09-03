## Verdict

**EXPLOITABLE** — The loop at line 12 reads from `frame[offset + i]` with a `length` parameter that is never validated against the vector's actual size. When a caller supplies `length` greater than the remaining space from `offset` to the end of the vector, the read iterates past the allocated buffer.

## Source

The `length` parameter is untrusted: it originates from a telemetry frame header that claims a window size, with no bounds validation before use.

## Fix

Add a bounds check immediately before the loop. Validate that both the length fits within the vector and the offset-plus-length sum does not overflow or exceed the vector size. The check must test the length first, then the offset, to prevent unsigned underflow in the subtraction:

```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    // Validate offset and length before any access
    if (offset >= frame.size()) {
        return 0;
    }
    
    // Check length first, then offset+length, to prevent unsigned underflow
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

The original code checked only `offset >= frame.size()` but did not validate that reading `length` bytes starting from `offset` stays within bounds. An attacker providing a large `length` value causes the loop to index beyond the vector's allocated buffer.

The fix adds two guards:
1. `length > frame.size()` — ensures the requested length does not exceed the entire vector
2. `offset > frame.size() - length` — ensures the sum `offset + length` does not exceed the vector size

These checks are evaluated in this specific order because `length` is checked first: if `length > frame.size()`, the subtraction `frame.size() - length` would wrap to a huge value in unsigned arithmetic, causing the second check to fail silently. By checking the length first, we ensure the subtraction cannot underflow.

The bounds validation happens in the same function that performs the read, before the loop begins, so every code path either validates or returns early.

## Behaviour changes

The function now returns `0` when `length` exceeds the available data or when `offset + length` would read past the end of the vector. This is appropriate for a checksum operation on a partial or malformed frame: returning a zero checksum for an invalid range allows the caller to detect and reject the malformed input.

Code that relies on the function to read beyond the buffer size will now return early instead. This is a defensive behaviour change: if such a caller exists, it was already working with out-of-bounds memory and the fix exposes that latent bug rather than hiding it.
