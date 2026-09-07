## Verdict
CONFIRMED

## Source
The vulnerable code is in `StackArrayIndexWrite.cpp` line 11, where the function `buildBadge` writes to a stack-allocated array using an unchecked index parameter:

```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels[slot] = level;  // line 11: no bounds check on slot
    return badge;
}
```

The array `levels` is fixed-size (32 elements) but `slot` is unconstrained, allowing writes beyond the array bounds.

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
Replace the unsafe subscript operator `[]` with the bounds-checking method `at()`. The `std::array::at()` method performs runtime bounds checking and throws `std::out_of_range` if the index exceeds the array size, preventing the stack-based buffer overflow. This is the idiomatic C++ safeguard for array access and converts a silent out-of-bounds write into a catchable exception.
