## Verdict

Confirmed. `buildBadge` writes to `badge.levels[slot]` using `std::array::operator[]`, which performs no bounds checking. `levels` is a fixed 32-byte array embedded in the `Badge` struct (stack-allocated in the caller once `buildBadge` returns by value / is inlined). Any caller-supplied `slot >= 32` writes past the end of `levels` within the `Badge` object, corrupting adjacent struct memory or stack contents - a classic stack-based buffer overflow (CWE-121).

## Source

`slot`, the `std::size_t` parameter to `buildBadge`, is attacker/caller-controlled and is used directly as an array index at line 11 with no validation before the write.

## Fix

### File: StackArrayIndexWrite.cpp
```cpp
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

struct Badge {
    std::array<std::uint8_t, 32> levels;
};

Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels.at(slot) = level;
    return badge;
}
```

## Explanation

The unchecked `operator[]` is replaced with `std::array::at()`, which performs a bounds check on every access and throws `std::out_of_range` if `slot` is not less than `levels.size()` (32). This eliminates the out-of-bounds write entirely: an invalid `slot` now produces a well-defined, catchable exception instead of undefined behavior that silently corrupts memory adjacent to `levels` on the stack.

`at()` is the standard, idiomatic bounds-checked accessor for `std::array` and requires no additional dependencies. The change is minimal and localized to the single unsafe write, preserving the function's behavior for all valid inputs (`slot` in `[0, 32)`) while converting the invalid-input case from a memory-safety violation into a normal C++ exception that the caller can validate against or catch. Callers that can supply an out-of-range `slot` should validate it against `badge.levels.size()` before calling, or catch `std::out_of_range`, depending on whether an invalid slot represents a programming error or an expected runtime condition in the caller's context.
