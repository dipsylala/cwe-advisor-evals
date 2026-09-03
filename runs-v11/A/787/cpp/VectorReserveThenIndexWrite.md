## Verdict

Out-of-bounds write confirmed. The code calls `reserve(count)` which allocates capacity but does not change the vector's size. The subsequent indexed assignment `packet[i]` writes beyond the vector's actual logical size (0), causing undefined behavior.

## Source

Line 15 in `buildPacket()`:
```cpp
packet[i] = fields[i];
```

The vector `packet` has been reserved with capacity for `count` elements but has not been resized. Its logical size remains 0, so `packet[i]` accesses memory outside the vector's initialized range.

## Fix

Replace `reserve(count)` with `resize(count)`:

```cpp
std::vector<PacketField> buildPacket(const std::vector<PacketField>& fields, std::size_t count) {
    std::vector<PacketField> packet;
    packet.resize(count);

    for (std::size_t i = 0; i < count; ++i) {
        packet[i] = fields[i];
    }

    return packet;
}
```

Alternatively, use `push_back()` in the loop instead of indexed assignment:

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

`std::vector::reserve(n)` allocates capacity for at least `n` elements but does not increase the vector's size. Accessing `packet[i]` on an empty vector (size 0) reads and writes uninitialized memory beyond the valid range, violating the vector's logical bounds.

`resize(count)` both allocates capacity and initializes the vector to contain `count` elements, making indexed access safe. Alternatively, `push_back()` increments the size with each insertion, keeping access in bounds.

The preferred fix is `resize()` when the final size is known upfront; `push_back()` when building incrementally.
