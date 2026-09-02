## Verdict
Real.

## Source
The `count` parameter passed to `buildPacket()` controls the loop bounds and write indices.

## Fix
Replace `reserve()` with `resize()` to set the vector's logical size to match capacity. This allows the subsequent indexed writes to land within the vector's valid range.

```cpp
std::vector<PacketField> buildPacket(const std::vector<PacketField>& fields, std::size_t count) {
    std::vector<PacketField> packet;
    packet.resize(count);  // Changed from reserve() to resize()

    for (std::size_t i = 0; i < count; ++i) {
        packet[i] = fields[i];
    }

    return packet;
}
```

Alternatively, use `push_back()` instead of indexed assignment:

```cpp
std::vector<PacketField> buildPacket(const std::vector<PacketField>& fields, std::size_t count) {
    std::vector<PacketField> packet;
    packet.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        packet.push_back(fields[i]);  // Alternative approach
    }

    return packet;
}
```

## Explanation
`std::vector::reserve(n)` allocates storage for at least `n` elements but does not change the vector's logical size. `operator[]` is undefined behaviour when the index exceeds the vector's size, even if the memory is allocated. The fix is to call `resize(count)` instead, which sets the size to `count` and zero-initializes the new elements, making indices 0 to count-1 valid for assignment. Alternatively, `push_back()` extends the size incrementally as each element is added, avoiding the index-bounds gap entirely. Both preserve the original function's contract and return value.

## Behaviour changes
Before: Writes to `packet[i]` when `i >= packet.size()`, producing undefined behaviour and potential memory corruption.

After: All writes are within the vector's valid logical range. Elements are properly tracked in the container, and the function returns a correctly-sized vector containing copies of the input elements.
