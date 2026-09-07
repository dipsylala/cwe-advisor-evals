## Verdict

exploitable

## Source

The `count` parameter passed to `buildPacket()` controls the loop bound and consequently the indices used to write to the `packet` vector.

## Fix

### File: VectorReserveThenIndexWrite.cpp

```cpp
#include <cstdint>
#include <cstddef>
#include <vector>
#include <algorithm>

struct PacketField {
    std::uint8_t tag;
    std::uint8_t value;
};

std::vector<PacketField> buildPacket(const std::vector<PacketField>& fields, std::size_t count) {
    std::vector<PacketField> packet;
    std::size_t actual_count = std::min(count, fields.size());
    packet.resize(actual_count);

    for (std::size_t i = 0; i < actual_count; ++i) {
        packet[i] = fields[i];
    }

    return packet;
}
```

## Explanation

The vulnerability occurs because `packet.reserve(count)` allocates capacity without changing the vector's size, which remains 0. The loop then uses `operator[]` to write at indices 0 through count-1, all of which are out-of-bounds for a zero-sized vector, resulting in undefined behavior. The fix replaces `reserve()` with `resize()` to actually set the vector's size, making all subsequent `operator[]` writes safe. The fix also validates `count` against the source vector's actual size using `std::min()` to prevent a secondary out-of-bounds read from `fields[i]`. After this change, the vector has exactly `actual_count` elements before any writes occur, so all indices used are guaranteed to be in bounds.

## Behaviour changes

The loop now processes `std::min(count, fields.size())` elements instead of the full `count`. If the caller passes `count > fields.size()`, the function will copy only the available elements from `fields` rather than attempting to read beyond the source vector's bounds. This is a defensive constraint that prevents two distinct out-of-bounds issues: the write out-of-bounds (CWE-787) and a read out-of-bounds (CWE-125/CWE-786). The function still returns a vector with copied elements; the behavior change is that it silently truncates at the source vector's boundary rather than causing undefined behavior.
