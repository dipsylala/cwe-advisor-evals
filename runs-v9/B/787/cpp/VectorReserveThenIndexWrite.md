## Verdict

CWE-787 (Out-of-bounds Write) - exploitable. Confidence: high.

## Source

`buildPacket(const std::vector<PacketField>& fields, std::size_t count)` - both parameters are caller-supplied; `count` in particular is an untrusted length value that drives the loop bound and is never checked against the destination's actual size.

## Fix

Vulnerable code (`VectorReserveThenIndexWrite.cpp`, line 15):

```cpp
std::vector<PacketField> buildPacket(const std::vector<PacketField>& fields, std::size_t count) {
    std::vector<PacketField> packet;
    packet.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        packet[i] = fields[i];   // out-of-bounds write: packet.size() is still 0
    }

    return packet;
}
```

Fixed code:

```cpp
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

`std::vector::reserve(count)` only grows the underlying capacity; it does not change `size()`, which stays 0 on a freshly constructed vector. `operator[]` performs no bounds check against capacity or size, so `packet[i] = fields[i]` writes through a pointer that is valid memory (reserved) but outside the vector's logical bounds for every iteration, which is undefined behaviour and a classic reserve/resize confusion. Replacing the indexed assignment with `packet.push_back(fields[i])` lets the container grow its own size on each insertion, so every write lands inside the vector's current bounds by construction; the earlier `reserve(count)` is kept so the loop still gets its single up-front allocation and no reallocation churn, but growth and bounds tracking are now the container's responsibility rather than hand-managed indexing. The `.at()` alternative was not used here because the defect is that no valid index exists yet, not that an index needs to be checked against an existing size - `push_back` addresses that directly, per the C++ CWE-787 guidance's "let the container grow itself" pattern.

## Behaviour changes

None beyond closing the weakness. `packet` ends up containing the same `count` elements, in the same order, with the same values as the original code intended; the return value, its size, and its contents for any input where the original did not already invoke undefined behaviour are unchanged. The read `fields[i]` is untouched - if `count` exceeds `fields.size()`, that expression was already an out-of-bounds read in the original code (a separate CWE-125 concern, not the write finding at line 15) and remains exactly as before; this fix does not add or remove any bounds check on `fields`.
