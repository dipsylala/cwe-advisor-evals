## Verdict
Out-of-bounds write confirmed. The code calls `vector::reserve()` to allocate capacity but then uses indexed access to write to the vector. Since `reserve()` does not change the vector's size, element access via `operator[]` at indices `[0..count-1]` is undefined behavior.

## Source
The vulnerability lies in the mismatch between capacity and size:
- Line 12: `packet.reserve(count)` allocates capacity for `count` elements but leaves size at 0.
- Line 15: `packet[i] = fields[i]` attempts indexed access and write at indices that exceed the actual vector size, resulting in out-of-bounds memory access.

## Fix
Replace `reserve()` with `resize()`:

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

Alternatively, use `push_back()` instead of indexed assignment to construct the vector incrementally.

## Explanation
`vector::reserve(size_t n)` pre-allocates capacity but does not modify the vector's logical size. Accessing elements beyond the current size via `operator[]` produces undefined behavior because the elements do not logically exist yet, even though the underlying memory has been allocated. `vector::resize(size_t n)` both allocates capacity and advances the size, making the elements accessible and properly constructed. This is the standard pattern when populating a vector by indexed access.
