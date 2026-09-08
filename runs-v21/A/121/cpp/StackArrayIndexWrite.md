## Verdict
Real vulnerability. Stack-based buffer overflow via unchecked array indexing.

## Source
The `buildBadge()` function accepts a `slot` parameter of type `std::size_t` without validation and uses it directly to index into a fixed-size `std::array<std::uint8_t, 32>`. Any `slot >= 32` causes out-of-bounds memory access, corrupting the stack.

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
The fix replaces the unchecked subscript operator `[slot]` with the bounds-checking method `.at(slot)`. The `std::array::at()` method performs runtime validation and throws `std::out_of_range` if the index is out of bounds, preventing the stack overflow. This is the idiomatic C++ mechanism for safe array access on standard containers.
