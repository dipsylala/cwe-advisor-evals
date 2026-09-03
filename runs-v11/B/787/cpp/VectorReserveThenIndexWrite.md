## Verdict

Exploitable. The vector's logical size is not updated when `reserve()` is called, leaving all subsequent `operator[]` writes out-of-bounds.

## Source

The `count` parameter in `buildPacket()` at line 10. This is external input that controls the loop bound and indexing into `packet`.

## Fix

**Vulnerable code:**
```cpp
std::vector<PacketField> packet;
packet.reserve(count);

for (std::size_t i = 0; i < count; ++i) {
    packet[i] = fields[i];  // Out-of-bounds write - vector size is still 0
}
```

**Fixed code:**
```cpp
std::vector<PacketField> packet;
packet.resize(count);  // Allocates and initializes count elements

for (std::size_t i = 0; i < count; ++i) {
    packet[i] = fields[i];
}
```

## Explanation

The vulnerability stems from confusion between `std::vector::reserve()` and `std::vector::resize()`. Calling `reserve(count)` allocates internal storage capacity but does not change the vector's logical size—it remains 0. Subsequent writes using `operator[]` therefore access memory outside the valid element range, resulting in an out-of-bounds write.

Replacing `reserve()` with `resize()` constructs and initializes `count` actual elements in the vector, making all subsequent index accesses in-bounds. The `operator[]` writes now target valid, allocated memory. This change uses the container's built-in bounds management rather than hand-rolled size tracking, eliminating the vulnerability.

## Behaviour changes

None. The fix preserves the original function's contract: it returns a vector with `count` copies of elements from `fields`, in the same order, with the same copy-constructed `PacketField` values.
