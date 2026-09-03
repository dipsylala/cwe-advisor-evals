## Verdict
Confirmed CWE-121 (Stack-based Buffer Overflow)

## Source
```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels[slot] = level;  // Line 11: unchecked array access
    return badge;
}
```

The `slot` parameter is written to the fixed-size array `badge.levels` (which has 32 elements) without bounds checking. Any value of `slot >= 32` causes a stack buffer overflow.

## Fix
```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    if (slot >= badge.levels.size()) {
        throw std::out_of_range("slot index out of range");
    }
    badge.levels[slot] = level;
    return badge;
}
```

Alternatively, use the bounds-checked accessor:
```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels.at(slot) = level;  // Throws std::out_of_range if slot >= size
    return badge;
}
```

## Explanation
Stack-based buffer overflows occur when a write to a stack-allocated buffer exceeds its bounds. Here, the `std::array<std::uint8_t, 32>` member `levels` has exactly 32 elements with valid indices 0–31. The function accepts `slot` as a `std::size_t` without validation, allowing any value to be passed. Writing to an out-of-bounds index corrupts the stack and enables code execution or denial-of-service attacks.

The fix adds a bounds check before the write and raises an exception if the index is invalid. Alternatively, `std::array::at()` provides the same protection with standard library semantics. Both approaches ensure the write stays within allocated bounds and fail safely rather than silently overflowing.
