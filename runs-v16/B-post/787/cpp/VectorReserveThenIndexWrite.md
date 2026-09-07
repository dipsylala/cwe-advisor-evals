## Verdict

Real vulnerability confirmed. The code calls `reserve(count)` which allocates capacity but does not change the vector's size. Writing to `packet[i]` when the vector size is 0 is out-of-bounds, even though the underlying storage is allocated. This produces undefined behavior and memory corruption.

## Source

Line 15: `packet[i] = fields[i];`

The `count` parameter originates from the caller and is untrusted. It flows into `packet.reserve(count)` at line 12, then into the loop bound at line 14, and finally into the unchecked subscript write at line 15.

## Fix

Change line 12 from:
```cpp
    packet.reserve(count);
```

To:
```cpp
    packet.resize(count);
```

**Complete fixed function:**

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

The root cause is confusing `reserve()` with `resize()`. The `reserve(count)` call allocates capacity but leaves the vector's logical size at 0. Subscript access via `operator[]` on a `std::vector` is not bounds-checked (per C++ specification, it is undefined behavior out-of-range), so writing to indices 0 through count-1 on a size-0 vector writes past the end of the valid element range into allocated but unowned memory.

The fix changes `reserve()` to `resize()`, which both allocates capacity *and* sets the vector's logical size to `count`. Now subscript writes to indices 0 through count-1 fall within the valid element range, and the out-of-bounds write is eliminated.

This follows the C++ guidance principle: "Let the container own its storage and growth" and "Reserve `operator[]` for an index already validated or structurally guaranteed, such as a loop bounded by `.size()`". After `resize(count)`, the loop bound `i < count` is structurally equivalent to `i < packet.size()`.

## Behaviour changes

The fixed code initializes all packet elements to default-constructed `PacketField` (zero-initialized) before overwriting them with the loop. The logical output is unchanged: packet contains a copy of the first `count` elements from the input fields vector. The timing difference is negligible for typical use.

Note: If `count > fields.size()`, the loop at line 15 will read out-of-bounds from the fields vector (CWE-125, out-of-bounds read). The current code has this issue independent of the CWE-787 write vulnerability. Fixing it requires validating count against fields.size() before the loop, which is outside the scope of CWE-787 remediation but is a related defect worth addressing in code review.
