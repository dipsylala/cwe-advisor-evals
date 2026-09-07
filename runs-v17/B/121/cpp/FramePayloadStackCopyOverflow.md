## Verdict

Exploitable. The `buildFrame` function copies `dataLen` bytes into a fixed-size 32-byte `std::array` without validating that the input fits. An attacker passing `dataLen > 32` causes a stack buffer overflow at line 16.

## Source

The vulnerability originates at the function parameter `dataLen` (line 10), which is attacker-controlled. The data source is the `data` pointer passed by the caller.

## Fix

### File: FramePayloadStackCopyOverflow.cpp

```cpp
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

struct Frame {
    std::array<std::uint8_t, 32> payload;
    std::size_t length;
};

Frame buildFrame(const std::uint8_t *data, std::size_t dataLen) {
    Frame frame{};
    
    // Validate that the incoming data length does not exceed the payload buffer capacity
    if (dataLen > frame.payload.size()) {
        throw std::length_error("Frame payload data exceeds maximum capacity of 32 bytes");
    }
    
    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

## Explanation

The fix adds a bounds check at function entry that validates `dataLen` against the payload buffer's actual capacity (32 bytes). If the input exceeds this limit, the function throws `std::length_error` with a descriptive message, explicitly rejecting the oversized input rather than silently corrupting the stack. The check uses `frame.payload.size()` to avoid hardcoding the capacity, so the bound stays in sync if the buffer size changes in the future. This follows the C++ guidance's principle of rejecting oversized input and matches the pattern of throwing `std::length_error` for length violations.

## Behaviour changes

The function now throws `std::length_error` if `dataLen > 32`, whereas the original code would silently overflow the buffer. Callers must handle this exception (via `try`/`catch` or by allowing it to propagate). This is the intended behaviour change: the function no longer accepts invalid input silently.

