## Verdict

Exploitable. The function accepts an unconstrained `std::size_t` index and writes to a fixed-size `std::array` without bounds checking, allowing out-of-bounds writes that corrupt adjacent stack memory.

## Source

**Location**: `evals/cases/121/cpp/StackArrayIndexWrite/StackArrayIndexWrite.cpp`, line 11

**Data flow**:
- Source: `slot` parameter (type `std::size_t`) to `buildBadge()` — unconstrained, attacker-controlled
- Sink: `badge.levels[slot] = level;` — unchecked `operator[]` access on `std::array<std::uint8_t, 32>`
- Vulnerability: No validation ensures `slot < 32`. Writing at any index >= 32 writes beyond the array bounds into adjacent stack memory, corrupting the stack frame.

## Fix

**Vulnerable code**:
```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels[slot] = level;  // Unchecked access - exploitable if slot >= 32
    return badge;
}
```

**Fixed code**:
```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels.at(slot) = level;  // Bounds-checked access - throws std::out_of_range if slot >= 32
    return badge;
}
```

## Explanation

The fix replaces the unchecked `operator[]` with `std::array::at()`, which performs bounds checking at runtime. The `at()` method throws `std::out_of_range` if the index is out of bounds, preventing the out-of-bounds write and stopping execution before memory corruption occurs. This enforces that only valid indices (0–31 for a 32-element array) can be used to access the array.

## Behaviour changes

**New exception contract**: The fixed function now throws `std::out_of_range` when `slot >= 32`. The original code exhibited undefined behavior (memory corruption) in this case; the fixed code instead signals the error explicitly. Callers must either:
1. Validate `slot < 32` before calling `buildBadge()` and handle the exception if validation is passed to a separate path
2. Wrap the call in a try/catch block to handle the exception
3. Change the function signature to return an error code

**No silent truncation**: The original behavior was undefined and could corrupt the stack. The fixed version rejects the invalid input rather than silently writing beyond bounds.

**No other behavior changes**: For valid indices (0–31), `.at()` is identical to `operator[]` — it returns a reference to the element and allows the assignment to proceed. Return type, the returned Badge value, and all other behavior remain unchanged for valid inputs.

**Verification**: The fix uses `std::array<T, N>::at()`, a standard C++11 method from the `<array>` header (already included in the original code). This method is available in all modern C++ standard libraries and compilers supporting C++11 or later.
