## Verdict

Out-of-bounds read confirmed. The loop iterates up to `length` times without validating that `offset + i` remains within the bounds of the `frame` vector, enabling reads beyond the allocated buffer.

## Source

Line 12: `checksum = (checksum << 5) ^ frame[offset + i];`

The function checks `offset >= frame.size()` but does not validate that the loop does not exceed `frame.size()` as `i` increments. If `offset + length > frame.size()`, subsequent iterations access unallocated memory.

## Fix

Bound the loop to prevent reading past the end of the vector:

```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < length && offset + i < frame.size(); ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];
    }

    return checksum;
}
```

The condition `offset + i < frame.size()` added to the loop guard ensures each index is within bounds before access.

## Explanation

The original code assumes `length` does not exceed available data from `offset` onward, but the caller can supply any value. The early check for `offset >= frame.size()` handles one edge case but leaves the bulk of the vulnerability open: a `length` that reaches or exceeds the remaining buffer capacity allows the loop to access memory beyond `frame.data() + frame.size()`.

Adding the bounds check to the loop condition stops iteration the moment the next index would exceed the buffer, preventing out-of-bounds reads. The checksum computation terminates safely at the buffer boundary rather than attempting to read beyond it.
