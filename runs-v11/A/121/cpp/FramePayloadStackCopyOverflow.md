## Verdict

Stack-based buffer overflow in `buildFrame()` at line 16. The function copies `dataLen` bytes into a fixed 32-byte buffer without validating the input length, allowing out-of-bounds writes.

## Source

```cpp
Frame buildFrame(const std::uint8_t *data, std::size_t dataLen) {
    Frame frame{};
    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        frame.payload[i] = data[i];  // Line 16: no bounds check; overflow if dataLen > 32
    }

    return frame;
}
```

## Fix

```cpp
#include <algorithm>

Frame buildFrame(const std::uint8_t *data, std::size_t dataLen) {
    Frame frame{};
    
    // Bounds check: cap length to buffer size
    frame.length = std::min(dataLen, frame.payload.size());

    for (std::size_t i = 0; i < frame.length; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

## Explanation

The vulnerability occurs because `dataLen` is accepted without validation against the 32-byte capacity of `frame.payload`. When `dataLen` exceeds 32, the loop writes beyond the array bounds, corrupting the stack.

The fix adds a bounds check using `std::min()` to limit `frame.length` to the maximum size of `frame.payload`. The loop then iterates only up to this safe limit, preventing out-of-bounds access. The `frame.length` field is updated to reflect the actual amount of data copied, preserving the contract that `frame.length` matches the valid payload size.

This approach prioritizes safety while maintaining backward compatibility—callers that provide data larger than the buffer will have it silently truncated, a common pattern for frame buffers with fixed capacity constraints.
