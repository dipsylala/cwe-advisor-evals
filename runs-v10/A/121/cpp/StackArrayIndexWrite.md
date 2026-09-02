## Verdict
**Confirmed**: Stack-based buffer overflow via unchecked array index write.

## Source
Line 11 in `StackArrayIndexWrite.cpp`:
```cpp
badge.levels[slot] = level;
```

The `slot` parameter is passed directly to an array subscript without bounds validation. The array `badge.levels` is fixed at 32 elements (`std::array<std::uint8_t, 32>`), but `slot` is of type `std::size_t` with no upper bound enforced by the function signature. An attacker-controlled value exceeding 31 writes past the allocated stack buffer.

## Fix
Add bounds checking before the array write:

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

Alternatively, use `.at()` instead of `operator[]`:

```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels.at(slot) = level;
    return badge;
}
```

The `.at()` method performs bounds checking and throws `std::out_of_range` on invalid indices, providing the same safety without explicit conditional logic.

## Explanation
`std::array::operator[]` performs no bounds checking and assumes the caller provides a valid index. Using an unchecked user-supplied or untrusted `slot` value directly as an index writes to arbitrary stack memory. The fix applies explicit bounds validation and either rejects out-of-range values via exception or uses the safe `.at()` accessor. This prevents writing beyond the array boundary and mitigates the stack overflow.
