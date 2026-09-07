## Verdict
The code has a real out-of-bounds write vulnerability. The vector is reserved with capacity but not resized, so its logical size remains 0. Accessing `packet[i]` writes to memory that is not part of the vector's active range.

## Source
Line 15 in VectorReserveThenIndexWrite.cpp:
```cpp
packet[i] = fields[i];
```

The issue occurs because `packet.reserve(count)` on line 12 allocates capacity but does not change the vector's size. The vector size remains 0, so any indexed access like `packet[i]` is out-of-bounds, even though the underlying memory is allocated.

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

Change line 12 from:
```cpp
packet.reserve(count);
```

to:
```cpp
packet.resize(count);
```

## Explanation
The `reserve()` method allocates capacity for future growth but does not change the vector's size. The `operator[]` on a vector accesses elements within the vector's logical size — if the size is 0, even a single indexed access is out-of-bounds.

`resize(count)` both allocates capacity AND sets the vector's logical size to `count`, initializing new elements with their default constructor (zero-initialized for `PacketField`). After resize, indexed access from 0 to count-1 is safe.

Alternatively, if preserving the exact state of uninitialized fields is needed, you could use `push_back()` in the loop instead; however, `resize()` is more efficient and produces correct behavior by ensuring the vector size matches the number of elements being written.
