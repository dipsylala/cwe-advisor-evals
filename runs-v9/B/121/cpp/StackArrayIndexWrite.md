## Verdict

exploitable
confidence: medium

## Source

The `slot` parameter (`std::size_t`) of `buildBadge(std::size_t slot, std::uint8_t level)`. No caller is present in the provided file, so `slot` is treated as untrusted input reaching this function's boundary without any validation performed before line 11.

## Fix

Vulnerable code:

```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels[slot] = level;  // unchecked index write into a 32-element stack array
    return badge;
}
```

Fixed code:

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

`badge.levels` is a `std::array<std::uint8_t, 32>` embedded in `Badge`, so it lives on the stack. `operator[]` on `std::array` performs no range check, so any `slot >= 32` writes past the end of `levels` into adjacent stack memory - a classic CWE-121 out-of-bounds write, exploitable if `slot` is attacker-influenced. Replacing `badge.levels[slot]` with `badge.levels.at(slot)` uses the array's own bounds-checked accessor, which validates the index against the container's actual declared size (`32`, via `size()`) rather than a separate hardcoded constant, and rejects an out-of-range index explicitly instead of writing past the buffer or silently truncating it.

## Behaviour changes

- Previously, an out-of-range `slot` caused undefined behavior (silent stack memory corruption, with no observable error at the call site). After the fix, an out-of-range `slot` (`>= 32`) causes `badge.levels.at(slot)` to throw `std::exception` `std::out_of_range`, which propagates out of `buildBadge` instead of returning a `Badge`. Any caller of `buildBadge` that does not already handle exceptions from this call must add a `try`/`catch` (or otherwise ensure out-of-range slots are never passed in) to avoid an unhandled-exception termination where the code previously (unsafely) returned a corrupted-but-non-throwing result.
- `<stdexcept>` was added to the includes for `std::out_of_range`, which `std::array::at` throws.
