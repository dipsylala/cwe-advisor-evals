## Verdict

Confirmed. `buildFrame()` copies `dataLen` bytes from the caller-supplied `data` buffer into `frame.payload`, a stack-resident `std::array<std::uint8_t, 32>`, using unchecked `operator[]` and never validates `dataLen` against the array's 32-byte capacity. Any call with `dataLen > 32` writes past the end of `payload` on the stack (CWE-121).

## Source

`dataLen`, the second parameter of `buildFrame(const std::uint8_t *data, std::size_t dataLen)`. It is attacker/caller-controlled (the function has no callers in this file and no internal bound), and nothing between the function entry and the loop constrains it.

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

    if (dataLen > frame.payload.size()) {
        throw std::length_error("buildFrame: dataLen exceeds payload capacity");
    }

    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

## Explanation

The sink is `frame.payload[i] = data[i]` inside the loop at line 16: `payload` is a fixed 32-byte stack array and the loop runs `dataLen` times with no upper bound, so `dataLen` values above 32 write past the array on the stack, corrupting adjacent stack memory (CWE-121). The fix adds an explicit length check - `dataLen` against `frame.payload.size()`, the destination's own declared capacity rather than a separate hardcoded `32` that could drift out of sync - before any byte is copied, and rejects an oversized request by throwing `std::length_error` instead of silently truncating it. This matches the knowledge base's guidance to validate length against the actual buffer capacity before every copy and to reject oversized input explicitly rather than truncate it (truncation would silently accept a corrupted/partial payload as if it were the full one). `frame.length` is now assigned only after the guard passes, so a rejected call never reports a `length` inconsistent with what was actually copied. The copy loop itself is unchanged and remains bounded by `.size()` once validated, per the C++-specific guidance's preference for keeping `operator[]` only where the index range is already provably in bounds; `.at()` was not substituted for `operator[]` because the upfront capacity check already makes every index in the loop provably in range, so a second, per-element bounds check would be redundant.

## Behaviour changes

- `buildFrame()` can now throw `std::length_error` when `dataLen > 32`. Previously it performed an out-of-bounds write (undefined behaviour, potentially crashing or corrupting the stack) instead of failing cleanly. Any caller that can pass more than 32 bytes must now be prepared to catch `std::length_error` (or let it propagate) instead of relying on the prior silent-corruption path.
- No behaviour change for any call with `dataLen <= 32`: the copy, `frame.length`, and the returned `Frame` are identical to before.
- No fix was verified against a compiler: no `g++`, `clang++`, or `cl.exe` was available in the environment. The fix was checked by hand instead - `std::length_error` and `<stdexcept>` are C++ standard library (verified from the standard, not invented), `std::array::size()` already exists on `payload`'s type, and no other new symbols, arguments, or return types were introduced.
