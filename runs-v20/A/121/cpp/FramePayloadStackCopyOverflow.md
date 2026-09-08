## Verdict

Confirmed. `buildFrame` copies `dataLen` attacker/caller-controlled bytes from `data` into `frame.payload`, a fixed 32-byte `std::array` on the stack, with no check that `dataLen` fits. Any call with `dataLen > 32` writes past the end of `payload` on the stack, corrupting adjacent memory (the `length` field, saved registers, or the return address depending on layout and optimization).

## Source

`dataLen`, the parameter passed in to `buildFrame(const std::uint8_t *data, std::size_t dataLen)` at line 10. It flows unchecked into the loop bound at line 14 and is used directly as the copy count into the fixed-size stack buffer at line 16.

## Fix

### File: FramePayloadStackCopyOverflow.cpp
```cpp
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

struct Frame {
    std::array<std::uint8_t, 32> payload;
    std::size_t length;
};

Frame buildFrame(const std::uint8_t *data, std::size_t dataLen) {
    Frame frame{};
    const std::size_t copyLen = std::min(dataLen, frame.payload.size());
    frame.length = copyLen;

    for (std::size_t i = 0; i < copyLen; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

## Explanation

The overflow happens because the loop bound (`dataLen`) is independent of the destination's actual capacity (`frame.payload.size()`, 32 bytes). The fix clamps the number of bytes copied to the smaller of the two with `std::min(dataLen, frame.payload.size())`, so the loop at line 14 can never write past index 31 of `payload` regardless of how large `dataLen` is.

`frame.length` is set to `copyLen` (the number of bytes actually copied) rather than the original `dataLen`, so the struct never claims a payload length larger than what is actually present in `payload` - keeping any later code that trusts `frame.length` to size a read over `frame.payload` safe as well, instead of just moving the overflow downstream.

This truncates rather than rejects oversized input outright: `buildFrame` has no error-reporting channel (it returns `Frame` by value, not a status code), so silently capping at capacity is the minimal change that preserves the function's signature and behavior for well-formed input while eliminating the out-of-bounds write. If oversized frames must be treated as a hard error by callers, the caller-side check should compare `dataLen` against `Frame{}.payload.size()` before calling `buildFrame`, or the function's signature should change to return a status alongside the frame - but that is a design change beyond the scope of this fix.
