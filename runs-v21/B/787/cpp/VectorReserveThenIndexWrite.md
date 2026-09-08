## Verdict

exploitable

## Source

Function parameter `count` in `buildPacket()` is used as a loop bound in line 15 without validation that the vector has actually been resized to accommodate the indexing operation.

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

The vulnerability stems from a misuse of `std::vector::reserve()`. The `reserve()` method allocates capacity for future growth but does not change the vector's size. When the loop then accesses `packet[i]` where `i` ranges from 0 to `count-1`, it is writing to elements that do not exist within the vector's logical bounds. This is undefined behaviour in C++ and constitutes an out-of-bounds write. The fix replaces `reserve(count)` with `resize(count)`, which both allocates capacity and initializes the vector to have exactly `count` valid elements. Now the subscript access in the loop operates within the vector's actual bounds.

## Behaviour changes

none
