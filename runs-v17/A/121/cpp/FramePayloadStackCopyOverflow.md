## Verdict

Confirmed. The function does not validate that the input size fits within the fixed-size `payload` buffer, allowing an attacker to trigger a stack-based buffer overflow by passing `dataLen > 32`.

## Source

```cpp
Frame buildFrame(const std::uint8_t *data, std::size_t dataLen) {
    Frame frame{};
    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        // Line 16: write beyond buffer if dataLen > 32
        frame.payload[i] = data[i];
    }

    return frame;
}
```

The `payload` field is a fixed 32-byte array. The loop copies `dataLen` bytes without bounds checking, overflowing the buffer if `dataLen > 32`.

## Fix

### File: FramePayloadStackCopyOverflow.cpp

```cpp
#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>

struct Frame {
    std::array<std::uint8_t, 32> payload;
    std::size_t length;
};

Frame buildFrame(const std::uint8_t *data, std::size_t dataLen) {
    Frame frame{};
    // Cap the length to the maximum payload size
    frame.length = std::min(dataLen, frame.payload.size());

    for (std::size_t i = 0; i < frame.length; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

## Explanation

The vulnerability occurs because the function trusts the caller to provide a `dataLen` that fits within the 32-byte `payload` buffer. If `dataLen` exceeds 32, the loop writes out-of-bounds memory on the stack, corrupting adjacent data or enabling code execution.

The fix caps `dataLen` to the payload's maximum capacity using `std::min()`. The frame's `length` field now accurately reflects how many bytes were actually copied. This ensures the copy loop never exceeds the buffer bounds, eliminating the overflow while preserving the frame structure's ability to track the original requested size for handling by the caller (via `frame.length`).

The added `#include <algorithm>` header provides `std::min()`.
