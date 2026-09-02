## Verdict

Exploitable. The `slot` parameter is an unchecked `std::size_t` used directly as an array index without bounds validation. When `slot >= 32`, this writes past the end of the 32-element `badge.levels` array, corrupting adjacent stack memory.

## Source

Function parameter: `std::size_t slot` (line 9, buildBadge)

## Fix

**Vulnerable code:**
```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels[slot] = level;  // Unchecked array subscript
    return badge;
}
```

**Fixed code:**
```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels.at(slot) = level;  // Bounds-checked subscript
    return badge;
}
```

## Explanation

The fix replaces the unchecked `operator[]` with the bounds-checking `.at()` method. When `slot >= 32`, `.at()` throws `std::out_of_range` instead of permitting an out-of-bounds write. This eliminates the stack overflow and makes the error condition explicit. The caller must handle the exception or allow it to propagate, rather than silently corrupting stack memory.

## Behaviour changes

- **New exception behaviour**: When `slot >= 32`, the function now throws `std::out_of_range` instead of performing undefined behaviour. The caller is responsible for catching and handling this exception or allowing the program to terminate.
- **For valid indices** (0-31): The function behaves identically—the array element is set and the Badge is returned normally.
- **Error reporting**: The overflow is now reported explicitly via exception, not silent undefined behaviour. This allows the caller to distinguish a valid write from an out-of-bounds access and respond accordingly.
