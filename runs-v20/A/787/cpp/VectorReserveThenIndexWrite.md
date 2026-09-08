## Verdict

Confirmed. `buildPacket` writes out of bounds.

## Source

`packet.reserve(count)` on line 12 only allocates capacity; it does not change `packet.size()`, which stays `0` because `packet` was just default-constructed. The loop at lines 14-16 then performs `packet[i] = fields[i]` for `i` in `[0, count)`. `std::vector::operator[]` performs no bounds checking, so every one of these writes lands past the end of the vector's actual (zero-length) contents — undefined behavior, and on typical implementations a heap out-of-bounds write for every iteration where `count > 0`.

## Fix

### File: VectorReserveThenIndexWrite.cpp
```cpp
#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <vector>

struct PacketField {
    std::uint8_t tag;
    std::uint8_t value;
};

std::vector<PacketField> buildPacket(const std::vector<PacketField>& fields, std::size_t count) {
    std::vector<PacketField> packet;
    packet.reserve(count);

    const std::size_t limit = std::min(count, fields.size());
    for (std::size_t i = 0; i < limit; ++i) {
        packet.push_back(fields[i]);
    }

    return packet;
}
```

## Explanation

`reserve()` and `resize()` are not interchangeable: `reserve()` only guarantees storage for future growth, while the number of live, indexable elements remains whatever it was before the call. Writing through `operator[]` is only valid for indices below `size()`; it never validates the index against capacity. Two changes fix this:

- Replace the index-write with `push_back`, which appends an element and grows `size()` by one each time, so every write lands in valid, live storage that `reserve` already pre-allocated (avoiding reallocation churn while remaining safe).
- Bound the loop by `std::min(count, fields.size())` rather than `count` alone. The original code also read `fields[i]` without bounds checking; since `count` is a caller-supplied value independent of `fields`, a `count` larger than `fields.size()` would cause an out-of-bounds *read* on `fields` even after the write side is fixed. Clamping the loop to the shorter of the two lengths keeps both sides of the assignment in bounds and preserves the function's intent (copy up to `count` fields into a freshly built packet) for any well-formed input where `count <= fields.size()`.

A test that calls `buildPacket` with a non-empty `fields` vector and a `count` equal to `fields.size()`, then checks the returned vector's `size()` and contents, exercises the fix directly; running it under AddressSanitizer or a debug STL (`_GLIBCXX_ASSERTIONS`/`_ITERATOR_DEBUG_LEVEL`) against the original code reliably trips a heap-buffer-overflow report on the `packet[i] = fields[i]` line, which the fixed version no longer triggers.
