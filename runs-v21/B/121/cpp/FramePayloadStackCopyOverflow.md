## Verdict

The finding is a true vulnerability. The `buildFrame` function copies an unbounded amount of input data into a fixed 32-byte stack-allocated `std::array` without validating the input length, causing a stack-based buffer overflow.

## Source

The vulnerability source is the `dataLen` parameter in `buildFrame`, which is attacker-controlled and represents the size of the input data to copy. There is no bounds check on this value.

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
    
    // Validate that input fits in the frame payload buffer
    if (dataLen > frame.payload.size()) {
        throw std::length_error("Data too large for frame payload");
    }
    
    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

## Explanation

The fix adds a validation check before the copy loop to ensure the input data length does not exceed the destination buffer's capacity (32 bytes). If the input is larger than the buffer can hold, the function throws `std::length_error`, rejecting the oversized input rather than silently truncating it or overflowing the buffer. This satisfies CWE-121's remediation requirement to "validate the incoming data's length against the destination buffer's actual capacity before every copy."

The validation uses `frame.payload.size()` to get the actual declared capacity of the array, ensuring the check stays synchronized with the array's actual size. The loop itself remains unchanged because the prior validation guarantees that the bounds are respected.

## Behaviour changes

- **New behavior**: The function now throws `std::length_error` if `dataLen > 32` bytes.
- **Caller must handle**: Any code calling `buildFrame` must handle the exception or allow it to propagate. If it was previously accepting oversized input silently (via truncation in the original unsafe code), the caller now receives an exception instead and must decide how to handle it.
- **Data integrity**: The function no longer silently accepts and truncates oversized input, which could have produced incorrect results (an over-long frame identifier could silently become a valid identifier for a different frame, or binary data could be corrupted mid-sequence).
