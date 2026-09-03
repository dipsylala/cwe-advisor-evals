## Verdict

**Real vulnerability. The stack-based buffer overflow is exploitable.** The `buildFrame()` function copies `dataLen` bytes into a fixed 32-byte stack buffer without validating that the input length fits, permitting an overflow of adjacent stack memory including the return address.

## Source

The vulnerable code is in `buildFrame()` at line 16:

```cpp
Frame buildFrame(const std::uint8_t *data, std::size_t dataLen) {
    Frame frame{};
    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        frame.payload[i] = data[i];  // SINK: unchecked write via operator[]
    }

    return frame;
}
```

**Data flow:** The `dataLen` parameter originates from an untrusted caller. The loop uses this length as the loop bound without checking whether it exceeds `frame.payload.size()` (32 bytes). When `dataLen > 32`, the assignment `frame.payload[i] = data[i]` writes past the buffer's declared boundary onto the stack.

**Why it is exploitable:** The buffer `frame.payload` is a `std::array<std::uint8_t, 32>` with inline storage on the stack. Writing beyond its 32-byte boundary corrupts adjacent stack objects, including the return address. An attacker who controls `data` and `dataLen` can craft a payload to overwrite the return address and redirect control flow.

## Fix

Validate that `dataLen` does not exceed the buffer capacity before performing the copy. Reject oversized input with an exception:

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
    
    // Validate input length against buffer capacity before any write
    if (dataLen > frame.payload.size()) {
        throw std::length_error("Frame payload exceeds maximum size of 32 bytes");
    }
    
    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

**What changed:** Added a bounds check before the copy loop that compares `dataLen` against `frame.payload.size()` and throws `std::length_error` if the input is too large. This validation uses the buffer's actual declared capacity (from `.size()`), ensuring the check cannot drift out of sync with the buffer's real size.

## Explanation

The fix closes the vulnerability by enforcing that no write can exceed the buffer's capacity. The check compares `dataLen` against the buffer's true size (`32`), not a hardcoded constant, so it remains correct if the buffer size changes. An attacker passing `dataLen = 100` will now trigger an exception before any overflow occurs, preventing the write of out-of-bounds data.

The exception signals the failure to the caller, ensuring the caller becomes aware that the input was rejected. This is safer than silently truncating to 32 bytes, which would substitute a different (potentially valid) payload without the caller's knowledge.

## Behaviour changes

**Breaking change for oversized input:**
- **Before:** A `dataLen > 32` causes silent stack corruption and undefined behavior.
- **After:** A `dataLen > 32` throws `std::length_error` and aborts the frame construction.

**For valid input (dataLen ≤ 32):**
- No behavioral change. The copy proceeds as before and the Frame is returned normally.

**Callers must handle the exception:**
- Any caller that invokes `buildFrame()` with untrusted input must wrap it in a try-catch or propagate the exception. If existing code does not have a handler, it will propagate up the call stack.

