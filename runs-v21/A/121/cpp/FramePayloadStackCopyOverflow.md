## Verdict
CONFIRMED - Stack-based buffer overflow due to unbounded copy to fixed-size array.

## Source
The vulnerable code copies `dataLen` bytes into a fixed 32-byte buffer without bounds checking, allowing data larger than 32 bytes to overflow the stack-allocated array.

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
    // Cap the copy length to the buffer size to prevent overflow
    frame.length = std::min(dataLen, frame.payload.size());

    for (std::size_t i = 0; i < frame.length; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

## Explanation
The vulnerability stems from copying `dataLen` bytes without validating it against the buffer capacity. The fix bounds the copy operation by limiting the loop to the minimum of the requested data length and the buffer size (32 bytes). The `frame.length` field now stores the actual number of bytes copied, not the unchecked input length, allowing callers to know how much data was actually stored. This prevents the overflow by ensuring the loop never writes past the buffer's bounds.
