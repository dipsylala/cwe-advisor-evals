## Verdict

The finding is real. The function copies `dataLen` bytes from the input buffer into `frame.payload`, a stack-allocated `std::array<std::uint8_t, 32>` with a fixed capacity of 32 bytes, without checking that the input fits. When `dataLen > 32`, the loop at line 16 writes past the array's end, corrupting the stack.

## Source

**File**: FramePayloadStackCopyOverflow.cpp  
**Lines**: 13–17 (loop structure), line 16 (sink)  
**Data flow**:
- Attacker-controlled source: `dataLen` parameter (std::size_t)
- No validation between entry and use
- Sink: `frame.payload[i] = data[i]` with `i` bounded only by `dataLen`, not by the array's 32-byte capacity
- Container: `std::array<std::uint8_t, 32>` (stack-allocated, inline storage)

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
    
    // Reject oversized input explicitly
    if (dataLen > frame.payload.size()) {
        throw std::length_error("Payload exceeds maximum frame size");
    }
    
    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

**Changes**:
- Added `#include <stdexcept>` for `std::length_error`
- Added explicit bounds check: if `dataLen > frame.payload.size()` (32 bytes), throw `std::length_error` before any writes
- The check uses the container's actual `.size()`, not a separate hardcoded constant, so it cannot drift out of sync

## Explanation

The vulnerability occurs because the loop writes `dataLen` iterations into a 32-byte fixed-size stack array without first validating that `dataLen ≤ 32`. The fix adds an explicit precondition check that rejects oversized input by throwing `std::length_error`, following the guidance's principle to "reject oversized input explicitly rather than silently truncating it." The check references the array's own `.size()`, ensuring the bound cannot drift from the actual buffer size. After the check passes, the loop is guaranteed not to overflow because `dataLen` has been proven ≤ 32. The exception propagates to the caller, which must decide how to handle the error (e.g., log it, return an error code, or abort gracefully), preventing silent data corruption or continued execution with corrupted state.

## Behaviour changes

- **Normal case (dataLen ≤ 32)**: Behavior is unchanged; the function copies data and returns the frame as before.
- **Oversized input (dataLen > 32)**: Previously caused undefined behavior (stack buffer overflow). Now throws `std::length_error` with message "Payload exceeds maximum frame size", preventing the overflow and signaling an error to the caller.
- **Callers must handle the exception**: Code that calls `buildFrame()` now needs to handle or propagate `std::length_error`, or allow it to terminate the program. If a caller was silently accepting oversized frames without realizing an overflow was occurring, this change makes the error explicit and testable.
