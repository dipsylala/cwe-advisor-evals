## Verdict
Confirmed stack-based buffer overflow. The `slot` parameter is used as an unchecked array index into a fixed-size array.

## Source
At line 11, `badge.levels[slot] = level;` writes to the array using an unsanitized `slot` value. The `levels` member is a `std::array<std::uint8_t, 32>`, so valid indices are 0–31. If `slot` >= 32, the write exceeds array bounds.

## Fix
Add a bounds check before the array access and throw an exception if the index is out of range:

```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    if (slot >= badge.levels.size()) {
        throw std::out_of_range("slot index exceeds array bounds");
    }
    badge.levels[slot] = level;
    return badge;
}
```

Alternatively, use `std::optional` or an error return type to propagate the invalid input without exception semantics.

## Explanation
Stack-based buffer overflow occurs when an array on the stack is written beyond its declared size. The `std::array` object `levels` occupies a fixed region on the stack; writing past its boundary corrupts adjacent stack memory, potentially overwriting return addresses, saved registers, or other local variables.

The fix validates that `slot` falls within `[0, badge.levels.size())` before indexing. This prevents out-of-bounds writes and ensures the array access is safe. The exception signals an invalid contract violation to the caller, allowing error handling at a higher level.
