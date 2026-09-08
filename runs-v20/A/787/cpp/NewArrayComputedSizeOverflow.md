## Verdict

Confirmed. `totalSize` is computed by summing two attacker-controlled 32-bit lengths (`headerLen`, `payloadLen`) in a 32-bit variable. The addition can wrap around (e.g. `headerLen = 0xFFFFFFF0`, `payloadLen = 0x20` produces `totalSize = 0x10`). The undersized buffer is then allocated with `new uint8_t[totalSize]`, and the two subsequent `memcpy` calls write `headerLen` and `payloadLen` bytes into it using the original, un-wrapped lengths - both writes overflow the heap allocation.

## Source

`headerLen` and `payloadLen`, the two `uint32_t` parameters to `ReassembleFragment`, are parsed directly from a remote peer's fragment header, per the function's own comment ("headerLen and payloadLen are parsed directly from the fragment's wire header fields, which the remote peer controls"). Both are fully attacker-controlled and unvalidated at the point they reach the size computation on line 15.

## Fix

### File: NewArrayComputedSizeOverflow.cpp
```cpp
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <limits>

// Reassembles a fragmented message from a custom binary transport protocol.
// Each fragment carries its own header and payload; headerLen and payloadLen
// are parsed directly from the fragment's wire header fields, which the
// remote peer controls.
//
// Returns nullptr if the fragment's advertised lengths cannot be honored
// safely (arithmetic overflow, or a combined size larger than this
// implementation is willing to allocate). Callers must check for nullptr
// before using the result.
uint8_t* ReassembleFragment(const uint8_t* headerData, uint32_t headerLen,
                             const uint8_t* payloadData, uint32_t payloadLen)
{
    // Widen the addition to 64 bits so the sum of two 32-bit lengths cannot
    // wrap around before it is validated. uint64_t can represent the sum of
    // any two uint32_t values without overflowing.
    uint64_t totalSize64 = static_cast<uint64_t>(headerLen) + static_cast<uint64_t>(payloadLen);

    // Reject combined sizes that either don't fit in size_t on this platform
    // or exceed a sane upper bound for a single reassembled message. This
    // also guards allocators/environments where size_t is 32 bits.
    constexpr uint64_t kMaxFragmentSize = 64ull * 1024 * 1024; // 64 MiB
    if (totalSize64 > kMaxFragmentSize || totalSize64 > std::numeric_limits<size_t>::max()) {
        return nullptr;
    }

    size_t totalSize = static_cast<size_t>(totalSize64);

    uint8_t* buffer = new uint8_t[totalSize];

    std::memcpy(buffer, headerData, headerLen);
    std::memcpy(buffer + headerLen, payloadData, payloadLen);

    return buffer;
}
```

## Explanation

The root cause is that `headerLen + payloadLen` was computed in a 32-bit `uint32_t`, so two attacker-supplied lengths that individually look reasonable can sum past `UINT32_MAX` and silently wrap to a small value. That wrapped value was then used as the allocation size for `new uint8_t[totalSize]`, while the two `memcpy` calls immediately afterward still used the original, non-wrapped `headerLen` and `payloadLen`. The result is a heap buffer sized for the wrapped (small) total but written with the full, attacker-controlled byte counts - a classic integer-overflow-to-buffer-overflow (CWE-190 leading to CWE-787).

The fix performs the same addition in `uint64_t`, a width wide enough that the sum of any two `uint32_t` values cannot overflow, so the true combined size is always computed correctly. That true size is then validated against both `size_t`'s range (so the cast down to `size_t` for `new[]` can never lose information) and an explicit sane upper bound for a single reassembled fragment (64 MiB), rejecting the fragment by returning `nullptr` rather than proceeding with an unsafe or absurdly large allocation. Only after this validation does the code allocate the buffer and perform the two `memcpy` calls, which now use lengths that are guaranteed to fit inside the buffer that was actually allocated. Because the allocation size and the two copy sizes are always the same values that passed validation, the writes can no longer exceed the buffer bounds.
