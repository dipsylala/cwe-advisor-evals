## Verdict
Out-of-bounds write confirmed. `std::vector::reserve()` allocates capacity but does not increase the vector's size. Accessing elements via `operator[]` on a zero-sized vector is undefined behavior and constitutes an out-of-bounds write.

## Source
```cpp
std::vector<PacketField> buildPacket(const std::vector<PacketField>& fields, std::size_t count) {
    std::vector<PacketField> packet;
    packet.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        packet[i] = fields[i];  // Out-of-bounds: vector size is 0
    }

    return packet;
}
```

## Fix
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
`std::vector::reserve(n)` pre-allocates memory for `n` elements but does not change the vector's logical size. Attempting to access elements via `operator[]` on a vector with size 0 results in out-of-bounds access.

The fix uses `push_back()` instead of direct indexing. This method both appends the element and increments the vector's size, ensuring all accesses remain within bounds. The `reserve()` call still serves its purpose by pre-allocating memory, avoiding reallocations during the loop.
