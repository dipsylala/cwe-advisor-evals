## Verdict

Confirmed. `buildPacket` writes out of bounds on every call where `count > 0`.

## Source

`count` (and the parallel `fields` vector, which the caller must supply with at least `count` elements) — the size used to drive the write loop.

## Fix

```cpp
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

    for (std::size_t i = 0; i < count; ++i) {
        packet.push_back(fields[i]);
    }

    return packet;
}
```

## Explanation

`std::vector::reserve(count)` only allocates capacity; it does not change `size()`, so `packet` is still an empty vector (size 0) after `packet.reserve(count)`. The loop then does `packet[i] = fields[i]` for `i` in `[0, count)`, and `operator[]` performs no bounds checking — every one of those writes lands past the end of the vector's logical (and, since size is 0, also its allocated-but-unconstructed) storage, which is undefined behavior and a classic out-of-bounds write. In practice this corrupts heap metadata or adjacent memory and can crash or be exploited depending on allocator layout.

The fix replaces the indexed write with `packet.push_back(fields[i])`, which appends an element and grows `size()` alongside the write, so each write always targets valid, constructed storage. The prior `reserve(count)` is still useful and kept: it pre-allocates capacity so the `push_back` calls in the loop don't trigger repeated reallocations, giving the same performance characteristics as the original (buggy) intent without the out-of-bounds access. An equally valid alternative is `packet.resize(count)` immediately after construction (instead of `reserve`), which gives the vector a real size of `count` so the original indexed-write loop becomes safe as written; `push_back` is preferred here because it avoids default-constructing then immediately overwriting every element.

Note that `fields[i]` on the read side is equally unchecked — the fix assumes the caller passes a `fields` vector with at least `count` elements (as documented by the function's implicit contract). If that cannot be guaranteed, use `fields.at(i)` or add an explicit `count <= fields.size()` check before the loop to fail safely instead of reading out of bounds on the input side too.
