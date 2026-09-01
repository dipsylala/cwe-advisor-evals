## Verdict
exploitable

## Source
The `slot` parameter is passed directly as an array index without bounds validation. The parameter is attacker-controlled through the function's public interface.

## Fix

**Vulnerable code:**
```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels[slot] = level;  // Unchecked array index access
    return badge;
}
```

**Fixed code:**
```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels.at(slot) = level;  // Bounds-checked access
    return badge;
}
```

## Explanation
The vulnerability is an unchecked write to a stack-allocated `std::array<std::uint8_t, 32>` via `operator[]`. The `slot` parameter is used directly as an array index without validation. When `slot >= 32`, the unchecked `operator[]` accesses memory beyond the array bounds, corrupting adjacent stack memory. The fix replaces `operator[]` with `.at()`, which performs bounds checking and throws `std::out_of_range` if `slot` is outside the valid range `[0, 32)`. This prevents the buffer overflow and surfaces the error condition to the caller.

## Behaviour changes
The function now throws `std::out_of_range` when `slot >= 32`, where the original code exhibited undefined behavior and memory corruption. Callers must handle this exception or allow it to propagate. For valid indices in the range `[0, 32)`, the function behaves identically to the original.
