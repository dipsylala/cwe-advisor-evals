## Verdict

Exploitable.

## Source

The `count` parameter passed to `buildPacket()` by an external caller, used without validation to size the vector operation.

## Fix

**Vulnerable code:**
```cpp
std::vector<PacketField> buildPacket(const std::vector<PacketField>& fields, std::size_t count) {
    std::vector<PacketField> packet;
    packet.reserve(count);  // Problem: reserve() allocates capacity but does not set size

    for (std::size_t i = 0; i < count; ++i) {
        packet[i] = fields[i];  // Out-of-bounds write: packet.size() is still 0
    }

    return packet;
}
```

**Fixed code:**
```cpp
std::vector<PacketField> buildPacket(const std::vector<PacketField>& fields, std::size_t count) {
    std::vector<PacketField> packet;
    packet.resize(count);  // resize() sets both capacity and size

    for (std::size_t i = 0; i < count; ++i) {
        packet[i] = fields[i];
    }

    return packet;
}
```

## Explanation

The vulnerability stems from confusion between `std::vector::reserve()` and `std::vector::resize()`. The `reserve()` call allocates memory but does not change the vector's logical size—it remains 0. Subsequent writes to `packet[i]` bypass the container's bounds checking because the container itself does not know these elements have been assigned. Using `resize(count)` instead sets both the capacity and the logical size, so indexing operations fall within the valid range. This ensures that element assignment remains within bounds and respects the vector's contract.

## Behaviour changes

None. The function now correctly produces a vector of size `count` with elements copied from `fields`, matching the original intent. The loop still iterates `count` times and assigns each element, but now within the container's valid logical range.
