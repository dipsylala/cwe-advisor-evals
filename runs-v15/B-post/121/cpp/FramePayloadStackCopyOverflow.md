## Verdict

**Vulnerable**: The function accepts an untrusted `dataLen` parameter and uses it to control a loop that writes to a fixed-size `std::array<std::uint8_t, 32>` without bounds validation. If `dataLen > 32`, the loop writes past the end of the buffer, causing a stack-based buffer overflow.

## Source

`data` pointer and `dataLen` parameter, both untrusted inputs to `buildFrame()`.

## Fix

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
    
    // Reject input that exceeds buffer capacity
    if (dataLen > frame.payload.size()) {
        throw std::length_error("Data length exceeds buffer capacity");
    }
    
    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

## Explanation

The fix adds a bounds check before the copy loop that explicitly validates `dataLen` against the buffer's actual capacity (`frame.payload.size()`, which is 32). If the input length exceeds the buffer capacity, the function throws `std::length_error` to reject the oversized value immediately, preventing any write past the buffer boundary. This follows the CWE-121 C++ guidance principle of "reject oversized input explicitly rather than silently truncating it" and ensures the caller receives clear feedback that the input is invalid rather than accepting corrupted data or silently discarding it.

## Behaviour changes

- **New exception**: Callers must now handle `std::length_error` thrown when `dataLen > 32`. Uncaught exceptions will terminate the program, so callers must wrap the call in a try/catch block or guarantee at the API boundary that `dataLen <= 32`.
- **Input validation**: Data longer than 32 bytes is now rejected instead of overflowing. Any code path that relies on truncation of oversized inputs will need to be updated to handle the exception or validate inputs before calling this function.
- **Safety improvement**: Stack buffer overflow vulnerability is eliminated; the function will no longer write past the buffer boundary under any circumstances.
