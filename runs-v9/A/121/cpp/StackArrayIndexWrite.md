## Verdict

Confirmed. `buildBadge` writes to `badge.levels[slot]` using an attacker/caller-controlled `slot` of type `std::size_t` with no bounds check. `levels` is a fixed-size, stack-allocated `std::array<std::uint8_t, 32>` embedded in `Badge`, which is itself constructed on the stack. Any `slot >= 32` writes past the end of the array, corrupting adjacent stack memory (other members, saved registers, or the return address depending on layout and optimization) — a classic CWE-121 stack-based buffer overflow via an unchecked array index write.

## Source

`E:/Github/cwe-advisor/evals/cases/121/cpp/StackArrayIndexWrite/StackArrayIndexWrite.cpp`, line 11:

```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels[slot] = level;   // line 11: unchecked index into a 32-byte stack array
    return badge;
}
```

`slot` is a function parameter with no visible caller-side validation in this translation unit; `operator[]` on `std::array` performs no bounds checking (it is equivalent to raw array indexing), so any value of `slot` outside `[0, 32)` is undefined behavior — most concretely, an out-of-bounds stack write.

## Fix

```cpp
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    if (slot >= badge.levels.size()) {
        // Reject the invalid slot; caller must handle the failure case.
        throw std::out_of_range("buildBadge: slot out of range");
    }
    badge.levels[slot] = level;
    return badge;
}
```

If exceptions are unsuitable for this codebase (e.g. compiled with `-fno-exceptions`, or the call site cannot propagate one), use `std::array::at()` instead of `operator[]`, which performs the same bounds check and throws `std::out_of_range` internally:

```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels.at(slot) = level;
    return badge;
}
```

Alternatively, if the function must never throw, change the return type to something like `std::optional<Badge>` (or add an output-parameter/bool status) and return an empty/failure result when `slot >= badge.levels.size()`, rather than silently clamping the index — clamping would mask a caller bug by making an invalid slot indistinguishable from writing to a valid one.

## Explanation

`std::array<std::uint8_t, 32>` is a fixed-size, stack-resident aggregate — it does not grow, and its `operator[]` is defined by the standard to be unchecked, exactly like indexing a C-style array. The vulnerability is not in `std::array` itself but in the missing validation of `slot` before it is used as an index: `buildBadge` accepts an arbitrary `std::size_t`, which can be any value up to `SIZE_MAX`, and uses it directly to compute a memory address inside the stack frame of `badge`. When `slot` is 32 or larger, the write lands outside the `levels` array, and because `Badge` (and thus `badge`) lives on the stack, this corrupts other stack-resident data — potentially other struct members, padding, saved registers, or (in less contained layouts) control data such as a return address — which is the defining characteristic of CWE-121.

The fix restores the bounds check that `operator[]` intentionally omits for performance. Using `at()` is the minimal, idiomatic change: it keeps the same array type and semantics but adds a runtime bounds check, throwing `std::out_of_range` on an invalid index instead of performing an unchecked write. An explicit `if (slot >= badge.levels.size())` check achieves the same effect while giving the caller control over the failure path (exception, error code, or `std::optional`), which is preferable when the function's error-handling contract needs to stay consistent with the rest of the codebase. Either approach should be applied at the point where untrusted or externally derived data first becomes an array index — validating earlier, only to index unchecked later, reopens the same gap.
