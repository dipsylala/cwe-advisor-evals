## Verdict

The code is vulnerable. Line 11 uses unchecked array indexing (`operator[]`) on a fixed-size stack array without validating that the index is within bounds.

## Source

The vulnerable sink is `operator[]` indexing on `std::array` with an unconstrained `std::size_t` parameter:

```cpp
badge.levels[slot] = level;  // slot is never checked
```

No caller-visible bounds check prevents `slot` from exceeding 31, allowing a stack-based buffer overflow.

## Fix

Replace the unchecked `operator[]` with `.at()`, which enforces bounds at runtime:

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
    badge.levels.at(slot) = level;  // Throws std::out_of_range if slot >= 32
    return badge;
}
```

## Explanation

The fix replaces unchecked `operator[]` with `.at()`, which performs runtime bounds checking on the array index. If `slot >= 32`, `.at()` throws `std::out_of_range` rather than writing past the array boundary. This eliminates the stack-based buffer overflow by rejecting out-of-bounds writes at the point of access. The caller must handle the exception or allow it to propagate to a higher-level handler.

## Behaviour changes

- **Normal case** (`slot` in range): Identical semantics; the assignment succeeds.
- **Out-of-bounds case** (`slot >= 32`): Previously wrote past the array, corrupting the stack. Now throws `std::out_of_range`, which either is caught by the caller or terminates the program. The caller's error handling determines whether this is logged, recovered, or reported to the end user.
