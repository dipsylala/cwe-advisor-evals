## Verdict

**Real issue confirmed.** The `buildBadge()` function writes to a fixed-size `std::array` using an unchecked index parameter. On any `slot >= 32`, `operator[]` produces undefined behaviour and corrupts the stack.

## Source

```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels[slot] = level;  // Line 11: unchecked index on std::array<uint8_t, 32>
    return badge;
}
```

`badge.levels` is a `std::array<std::uint8_t, 32>` with indices 0–31. The parameter `slot` is unsanitized and may exceed this range.

## Fix

```cpp
Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels.at(slot) = level;  // Use .at() for bounds checking
    return badge;
}
```

Replace `operator[]` with `.at()`, which throws `std::out_of_range` if `slot >= 32`.

## Explanation

The C++ guidance requires bounds checking on any container access where the index depends on input. `operator[]` on `std::array` is unchecked — the check must be explicit.

`.at()` performs the check: if the index is out of range, it raises `std::out_of_range` rather than silently writing past the buffer. A caller can catch the exception or let it propagate and terminate, either of which is preferable to silent stack corruption.

This is idiomatic C++ and requires no additional includes beyond what the original already has (`<array>`).

## Behaviour changes

- **On valid index (0–31):** unchanged — the write proceeds normally.
- **On invalid index (≥32):** now throws `std::out_of_range` instead of undefined behaviour. Any caller must handle or propagate this exception. If the caller has no exception handler, the exception terminates the program — which is safer than stack corruption leading to a subtle crash or exploit later.
