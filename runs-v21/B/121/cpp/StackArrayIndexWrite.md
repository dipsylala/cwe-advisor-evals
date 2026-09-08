## Verdict

Confirmed. Stack-based buffer overflow via unchecked array indexing on a fixed-size `std::array` member. The `slot` parameter is unconstrained and directly used as an index without bounds validation.

## Source

The vulnerability lies in the `buildBadge()` function. The `slot` parameter (type `std::size_t`) is passed directly as an index to `badge.levels`, a `std::array<std::uint8_t, 32>` with fixed capacity 32. The function does not validate that `slot` falls within [0, 31], so any caller passing `slot >= 32` will trigger an out-of-bounds write that overflows the stack.

## Fix

### File: StackArrayIndexWrite.cpp

```cpp
#include <array>
#include <cstddef>
#include <cstdint>

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

The fix replaces the unchecked `operator[]` access on line 11 with `.at()`, which performs bounds checking at runtime. If `slot >= 32`, `.at()` throws `std::out_of_range` instead of permitting the out-of-bounds write. This closes the stack buffer overflow by rejecting invalid input explicitly rather than corrupting adjacent stack memory. The `.at()` method is standard C++ (available since C++11) and incurs minimal runtime overhead—a single bounds comparison.

## Behaviour changes

- **Input validation**: Calls with `slot >= 32` now throw `std::out_of_range` instead of silently overflowing the buffer. Callers must handle or propagate this exception.
- **Return contract**: Under normal operation (0 <= slot < 32), the function still returns the same `Badge` object with the level correctly assigned. On invalid input, an exception is raised before returning.
- **Performance**: Negligible—a single comparison operation per call.
