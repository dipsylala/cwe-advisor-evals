## Verdict

VULNERABLE. Unchecked array indexing causes stack-based buffer overflow.

## Source

Line 11, `StackArrayIndexWrite.cpp`:
```cpp
badge.levels[slot] = level;
```

The `slot` parameter is an unsanitized `std::size_t` passed directly to `operator[]` on a fixed-size `std::array<std::uint8_t, 32>`. No bounds validation occurs before the write.

## Fix

Replace unchecked `operator[]` with `.at()` to enforce bounds checking:

```cpp
#include <array>
#include <cstddef>
#include <cstdint>

struct Badge {
    std::array<std::uint8_t, 32> levels;
};

Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels.at(slot) = level;  // Use .at() instead of operator[] for bounds checking
    return badge;
}
```

## Explanation

The vulnerability stems from `operator[]` on `std::array` being unchecked — it performs no bounds validation and produces undefined behavior if the index is out of range. When `slot >= 32`, the write corrupts stack memory beyond the 32-element array.

The fix replaces `operator[]` with `.at()`, which performs runtime bounds checking and throws `std::out_of_range` if the index exceeds the array's size. This converts undefined behavior into explicit, catchable exception handling. The caller must decide whether to catch and handle the exception or allow it to propagate as a program error — either way, the out-of-bounds write is prevented.

## Behaviour changes

- **Normal operation (slot < 32):** Behavior unchanged; `.at()` succeeds and assigns the value.
- **Out-of-bounds access (slot >= 32):** `.at()` throws `std::out_of_range` exception instead of silently corrupting stack memory. Calling code must handle this exception or accept program termination.
- **Exception safety:** Caller now receives notification of invalid input rather than undefined behavior. Error handling is required at the call site.
