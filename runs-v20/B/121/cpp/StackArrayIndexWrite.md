## Verdict

exploitable

- cwe_id: CWE-121 (Stack-based Buffer Overflow)
- location: StackArrayIndexWrite.cpp, line 11
- confidence: high

## Source

`buildBadge(std::size_t slot, std::uint8_t level)` takes `slot` as a function parameter with no caller in the provided file, so it is treated as externally-controlled input (the function is a public entry point with no internal validation). `slot` flows unchanged from the parameter directly into the indexing expression on line 11 - there is no intermediate check, cast, or clamp anywhere in the function body.

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

`badge.levels` is a `std::array<std::uint8_t, 32>` embedded inline in `Badge`, so it lives on the stack; `operator[]` performs no bounds checking, so any `slot >= 32` writes past the end of the array into adjacent stack memory - the classic CWE-121 pattern for a C++ `std::array`. The fix replaces the unchecked `operator[]` write with `.at(slot)`, the bounds-checked accessor `std::array` provides for exactly this case. `.at()` validates the index against the container's own `size()` before returning a reference, and throws `std::out_of_range` instead of performing the write when `slot` is out of bounds, closing the out-of-bounds write while leaving in-bounds behaviour identical to the original code.

## Behaviour changes

- For `slot < 32` (the array's actual size): no behaviour change - `.at()` returns the same reference `operator[]` would have, and `level` is written to the same slot.
- For `slot >= 32`: the original code had undefined behaviour (an out-of-bounds stack write); the fixed code throws `std::out_of_range` instead of writing. This is the intended effect of the fix - it converts a silent memory-corrupting write into a reported, catchable failure - but it is a visible behaviour change for any caller that was previously relying on (or unaware of) out-of-range calls appearing to "succeed": such a caller must now either validate `slot` before calling `buildBadge`, or catch `std::out_of_range` around the call. No caller is present in the provided file to update.
- assumptions: `slot` was treated as untrusted/unvalidated input because the single provided file shows no caller and no internal check constraining it; if a caller elsewhere already clamps `slot` to `[0, 32)`, the finding would still be worth hardening at this function (per the guidance's "re-check at each function that writes into a fixed-size buffer, since it may be reachable from another caller") but would be lower severity than assumed here.
- verification: no C++ compiler (`g++`/`clang++`) was reachable in this environment. Manual check performed instead: `.at()` is a standard member of `std::array` declared in the `<array>` header already included by the file, so no new `#include` is required; its signature (`reference at(size_type pos)`, throwing `std::out_of_range`) matches the usage `badge.levels.at(slot) = level` with `slot` as `std::size_t` and no other call sites exist in this file to update.
