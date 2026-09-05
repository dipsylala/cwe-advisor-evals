## Verdict

Exploitable - CWE-787 Out-of-bounds Write

## Source

**Location:** evals/cases/787/cpp/VectorReserveThenIndexWrite/VectorReserveThenIndexWrite.cpp, line 15

**Source:** `count` parameter (external input controlling the loop bound)

**Sink:** `packet[i] = fields[i]` (operator[] write to vector without bounds validation)

**Issue:** `reserve(count)` allocates capacity but does not increase the vector's size from 0. Subsequent writes via `packet[i]` access memory that is not part of the vector's logical size, causing an out-of-bounds write into unowned memory.

## Fix

**Before:**
```cpp
std::vector<PacketField> buildPacket(const std::vector<PacketField>& fields, std::size_t count) {
    std::vector<PacketField> packet;
    packet.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        packet[i] = fields[i];
    }

    return packet;
}
```

**After:**
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

## Explanation

The fix replaces `reserve(count)` with `resize(count)`. `reserve()` allocates storage capacity without modifying the vector's size, leaving it at 0. `resize()` creates the required number of default-constructed `PacketField` elements and updates the size to `count`, making the memory logically part of the vector. Now `packet[i]` accesses valid elements within the vector's bounds. The write at line 15 is no longer out-of-bounds because the indexed access is within the range `[0, count)` that `resize()` established.

## Behaviour changes

The vector now contains `count` default-initialized `PacketField` elements before the assignment loop runs, so each element is constructed twice: once by `resize()` (default-initialized to zero values) and once by the assignment. For non-trivial types this may have a minor performance cost, but correctness takes precedence. If the performance matters, the alternative is to use `push_back()` in the loop instead, which constructs each element exactly once. The return type and function signature remain unchanged; the caller sees the same vector returned with `count` copied elements.
