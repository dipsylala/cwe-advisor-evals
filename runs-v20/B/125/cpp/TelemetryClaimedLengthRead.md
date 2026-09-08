## Verdict

exploitable

## Source

The `offset` and `length` parameters of `checksumTelemetryWindow()` (`TelemetryClaimedLengthRead.cpp:5`). No caller is present in the supplied file, so per the function's own name and the finding's naming ("claimed length"), these are treated as untrusted values describing a window inside a telemetry `frame` - a caller-supplied window that has not been validated against the buffer's actual size before this function uses it. The only check present, `offset >= frame.size()` (line 6), validates `offset` alone and never constrains `length` against the remaining space in `frame`.

## Fix

### File: TelemetryClaimedLengthRead.cpp
```cpp
#include <cstddef>
#include <cstdint>
#include <vector>

std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (length > frame.size() || offset > frame.size() - length) {
        return 0;
    }

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < length; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];
    }

    return checksum;
}
```

## Explanation

`frame[offset + i]` (line 12) is a `std::vector<std::uint8_t>::operator[]` read, which performs no bounds checking. The original guard only rejected `offset >= frame.size()`; it never constrained `length`, so any call where `offset + length` exceeds `frame.size()` walks the loop past the end of the vector's buffer, reading adjacent heap memory. The fix replaces the single-sided check with the two-part guard the buffer's own size drives: reject outright when `length > frame.size()`, and only once that holds (so the subtraction cannot wrap) reject when `offset > frame.size() - length`. Both conditions must be evaluated in that order because unsigned arithmetic wraps - checking `offset + length <= frame.size()` directly would let a large `offset` overflow the addition and slip past the guard, and computing `frame.size() - length` before confirming `length <= frame.size()` would do the same to the subtraction for an oversized `length`, which is exactly the case this finding is about. Once both checks pass, `offset + length <= frame.size()` is guaranteed without overflow, so every `frame[offset + i]` in the loop is in range.

## Behaviour changes

- For any call where `offset + length` would have exceeded `frame.size()`, the function previously performed an out-of-bounds read (undefined behaviour: garbage data, a crash, or a wrong checksum depending on what followed the buffer in memory). It now returns `0` deterministically, matching the error-handling convention the function already used for an out-of-range `offset` alone. This is the intended effect of the fix, not an incidental change.
- For every call where `offset + length <= frame.size()` (all previously well-defined calls, including `length == 0`), the computed checksum is unchanged - the loop body, its bounds, and the returned value are identical to before.
- No parameters, return type, or externally visible signature changed.

## Verification

No C++ compiler or checker (`g++`, `clang++`, `cl.exe`) was found on the PATH in this environment, so the fix was verified by manual read rather than compilation. The fix introduces no new symbols, includes, or APIs beyond `frame.size()`, which the original code already called - so there is nothing new to check against a header or library. Traced by hand: (1) the `||` short-circuits, so `frame.size() - length` is only evaluated once `length <= frame.size()` is already known, eliminating the unsigned-underflow path; (2) after both checks pass, `offset <= frame.size() - length` implies `offset + length <= frame.size()` with no overflow, so every loop index `offset + i` for `i` in `[0, length)` stays within `[0, frame.size())`; (3) the `length == 0` and `offset == frame.size()` boundary cases were traced and both return `0` with the loop never executing, consistent with the pre-fix behaviour for those same inputs.
