## Verdict

Confirmed. `packet.reserve(count)` only reserves capacity; it does not change `packet.size()`, which stays 0. The loop then performs `packet[i] = fields[i]` for `i` in `[0, count)`, and `std::vector::operator[]` performs no bounds check, so every iteration writes past the end of `packet`'s valid range (`size() == 0`) into unallocated/uninitialized memory - undefined behaviour and an out-of-bounds write (CWE-787) regardless of how `count` relates to `fields.size()`.

## Source

- Sink: `packet[i] = fields[i];` at line 15 of `VectorReserveThenIndexWrite.cpp` - `std::vector<PacketField>::operator[]` used to write into `packet`.
- Root cause: `reserve(count)` (line 12) is confused with `resize(count)`. `reserve` allocates storage for at least `count` elements but leaves `size()` at 0; only `resize`, `push_back`, `emplace_back`, or `insert` change `size()`. The write index `i` (0..count-1) is therefore never within `packet`'s valid, constructed range at the time of the write.
- `count` is a caller-supplied parameter with no upper bound expressed in the function signature, but the defect fires even for a well-formed call (e.g. `count == fields.size()`), since the bug is in how `packet` is grown, not in the value of `count` itself.
- Sink contract: the call produces no return value used by the caller for error checking; `operator[]` out of range is undefined behaviour - it does not throw or return a status, so nothing downstream can detect the failure. The fix must make the write itself safe rather than adding a check for a signal `operator[]` never produces.

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
    packet.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        packet.push_back(fields[i]);
    }

    return packet;
}
```

## Explanation

The fix replaces the indexed write `packet[i] = fields[i]` with `packet.push_back(fields[i])`, so `packet` grows its own size as elements are added instead of being written through an index that was never inside its constructed range. `reserve(count)` is kept: it still pre-allocates storage for `count` elements so the subsequent `push_back` calls do not trigger reallocation, but it no longer needs to (and does not need to) establish `size()` itself - `push_back` does that safely on each call, and the standard guarantees it never writes outside the vector's own storage. This removes the out-of-bounds write entirely: there is no longer any index-based write into `packet` for `operator[]`'s unchecked-access behaviour to violate. The read side, `fields[i]`, is unchanged - it relies on the same implicit precondition it already had (that `count` does not exceed `fields.size()`), which is outside the reported write defect and outside this fix's scope.

## Behaviour changes

- `packet` is populated via `push_back` instead of via indexed assignment; the resulting vector's contents and size (`count` elements, or fewer if `fields` throws/ends earlier) are identical to what the caller intended when `count <= fields.size()`.
- Where `count` exceeded `fields.size()` in a prior invocation, the vulnerable code had undefined behaviour on both the read (`fields[i]`) and the write (`packet[i]`) once `i` reached `fields.size()`; the fixed code still reads `fields[i]` unchecked (unchanged from the original, out of scope for this CWE-787 write fix), but it no longer additionally corrupts memory via the write side once that unchecked read returns a value - the write is always into valid, size-tracked storage.
- No change to the function's signature, return type, or the values written to `packet` for any input where `count <= fields.size()`.

Check performed: no C++ compiler was reachable in this environment (`g++`, `clang++`, `cl`, `c++` all absent). Verified by manual read: `push_back` is a standard `std::vector<T>::push_back(const T&)` member (declared via the already-included `<vector>` header), its argument type (`const PacketField&` from `fields[i]`) matches the container's element type, and no other symbol, header, or call signature in the file was introduced or altered.
