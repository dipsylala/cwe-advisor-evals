## Verdict

Exploitable. The function accepts an unconstrained `dataLen` parameter and writes `dataLen` bytes into a fixed-size `std::array<std::uint8_t, 32>` without validating that the input fits within the array's 32-byte capacity. When `dataLen > 32`, the loop at line 14-16 writes past the allocated buffer's bounds, corrupting adjacent stack memory.

## Source

The `data` parameter passed to `buildFrame()` is caller-controlled and has no enforced upper bound. The `dataLen` parameter reflects the length of this caller-provided buffer but is not validated against the destination buffer's capacity.

## Fix

**Vulnerable code:**

```cpp
Frame buildFrame(const std::uint8_t *data, std::size_t dataLen) {
    Frame frame{};
    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        // SAST FINDING: CWE-121 (Stack-based Buffer Overflow) reported here. Sink is the next statement.
        frame.payload[i] = data[i];  // No bounds check; writes past array end if dataLen > 32
    }

    return frame;
}
```

**Fixed code:**

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
    
    if (dataLen > frame.payload.size()) {
        throw std::length_error("Input data exceeds payload capacity");
    }
    
    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

## Explanation

The fix validates the input length against the destination buffer's actual capacity before any write occurs. The bounds check uses `frame.payload.size()` rather than a hardcoded constant, ensuring the validation stays correct if the buffer size changes in future. When the input exceeds capacity, an exception is thrown immediately, rejecting the oversized input explicitly rather than silently truncating it or allowing an overflow. This prevents the loop from ever writing past the array's bounds, closing the stack-based buffer overflow. The fix also requires adding `#include <stdexcept>` to support `std::length_error`.

## Behaviour changes

- **Added**: `#include <stdexcept>` header for exception support
- **Added**: bounds check using `frame.payload.size()` before the copy loop
- **Added**: throws `std::length_error` exception if input exceeds the payload buffer's 32-byte capacity
- **Changed**: function now has exception-throwing behaviour; callers must handle or propagate `std::length_error`
- **Preserved**: `frame.length` is still set to the validated input length
- **Preserved**: loop still copies exactly `dataLen` bytes into the payload
- **Preserved**: return value is still the populated Frame struct
