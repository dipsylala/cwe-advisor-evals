## Verdict

Real issue. The code uses `vector::reserve()` which only allocates capacity but does not change the vector's size. Subsequent indexed access via `operator[]` performs an out-of-bounds write on an empty vector.

## Source

VectorReserveThenIndexWrite.cpp, lines 11-16:
```cpp
std::vector<PacketField> packet;
packet.reserve(count);

for (std::size_t i = 0; i < count; ++i) {
    packet[i] = fields[i];  // Out-of-bounds: vector size is 0, capacity is count
}
```

The vector's size is 0 after `reserve()`, making all index accesses undefined behavior.

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

Changed `packet.reserve(count)` to `packet.resize(count)` on line 12. The `resize()` function sets both the capacity and the actual size of the vector to `count`, making the indexed assignments valid. `reserve()` only pre-allocates capacity without changing the size, leaving the vector empty and making `operator[]` access undefined behavior.

