## Verdict

CWE-121: Stack-based Buffer Overflow confirmed. The `buildBadge()` function performs an unchecked array write using a caller-supplied index (`slot`) without validating it is within the bounds of the fixed-size `levels` array (32 elements).

## Source

```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels[slot] = level;  // Line 11: no bounds check on slot
    return badge;
}
```

The `std::array<std::uint8_t, 32> levels` member has valid indices 0–31. The function accepts `slot` as `std::size_t` (unsigned, up to 2^64 on 64-bit systems) with no validation, allowing any value to index the array. An out-of-bounds write corrupts the stack.

## Fix

```cpp
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

struct Badge {
    std::array<std::uint8_t, 32> levels;
};

Badge buildBadge(std::size_t slot, std::uint8_t level) {
    if (slot >= 32) {
        throw std::out_of_range("Badge slot index out of range");
    }
    Badge badge{};
    badge.levels[slot] = level;
    return badge;
}
```

## Explanation

The fix adds a bounds check before the array write. If `slot >= 32`, the function throws `std::out_of_range`, rejecting out-of-bounds writes and signaling the error to the caller.

**Why this works:**
- `std::array` does not perform bounds checking on the `operator[]` access; you must validate the index yourself before using it.
- Throwing an exception on invalid input is idiomatic C++ for precondition violations and prevents silent memory corruption.
- The `#include <stdexcept>` is added to provide `std::out_of_range`.

**Alternative approaches:**
- Use `badge.levels.at(slot) = level;` instead of `operator[]`; `.at()` throws automatically on out-of-bounds access. However, this would typically require catching the exception in the calling code.
- Return `std::optional<Badge>` to allow the function to signal failure without throwing, requiring the caller to check the result.

The bounds check is the most direct and efficient defense: it prevents overflow by design rather than relying on undefined behavior or exception handling.
