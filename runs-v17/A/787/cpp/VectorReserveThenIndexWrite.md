## Verdict
Out-of-bounds write confirmed. The code calls `reserve()` which allocates capacity but does not change vector size, then immediately accesses elements via `operator[]` at indices [0, count-1], which are beyond the vector's logical size of 0.

## Source
```cpp
std::vector<PacketField> packet;
packet.reserve(count);

for (std::size_t i = 0; i < count; ++i) {
    packet[i] = fields[i];  // Line 15: out-of-bounds access
}
```

## Fix

### File: VectorReserveThenIndexWrite.cpp
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
    packet.resize(count);

    for (std::size_t i = 0; i < count; ++i) {
        packet[i] = fields[i];
    }

    return packet;
}
```

## Explanation
The vulnerability occurs because `reserve()` allocates memory but does not establish a valid range for `operator[]` access. The vector's size remains 0 even after reserving capacity for `count` elements. Accessing `packet[i]` when i >= size() is undefined behavior.

The fix changes `reserve(count)` to `resize(count)`, which extends the logical size of the vector to `count` elements and default-constructs each one. Now `operator[]` accesses are within bounds [0, count-1]. Alternatively, `push_back()` could be used in the loop instead, but `resize()` is more efficient here since the number of elements is known upfront.
