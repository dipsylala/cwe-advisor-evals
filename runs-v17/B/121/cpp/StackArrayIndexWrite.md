## Verdict

The finding is confirmed. Line 11 uses unchecked `operator[]` to write into a fixed-size stack-allocated `std::array`, allowing an out-of-bounds write when `slot >= 32`.

## Source

The `slot` parameter to `buildBadge()` is user-controlled and unbounded. It flows directly to the sink at line 11.

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

The fix replaces the unchecked `operator[]` with `.at()`, which performs bounds checking at runtime. If `slot >= 32`, `.at()` throws `std::out_of_range`, preventing the out-of-bounds write and corrupting adjacent stack memory. The caller can catch and handle the exception or allow it to propagate up the call stack. This satisfies the CWE-121 C++ guidance to use `.at()` wherever the index is not provably in range, rejecting oversized values rather than permitting overflow.

## Behaviour changes

- **Normal case (slot < 32)**: Behaviour unchanged; the element is set and the Badge is returned.
- **Out-of-bounds case (slot >= 32)**: Instead of undefined behaviour and stack corruption, `std::out_of_range` is thrown. The caller must decide whether to catch it or allow program termination. This is the correct safety-first response; silent truncation would trade memory corruption for data loss.
