## Verdict

The vulnerability is an integer overflow in the size calculation that causes heap buffer allocation to reserve insufficient space, followed by out-of-bounds write during `memcpy`. The fix is to detect and reject size overflows before allocation.

## Source

The attacker controls `headerLen` and `payloadLen` as 32-bit values from the wire protocol. Line 15 adds them without checking for wraparound:

```
uint32_t totalSize = headerLen + payloadLen;
```

For example, `headerLen = 0xFFFFFFF0` and `payloadLen = 0x20` produce `totalSize = 0x10` due to unsigned integer wraparound. The subsequent `new uint8_t[0x10]` allocates only 16 bytes, but lines 20–21 write `0xFFFFFFF0 + 0x20` bytes total, causing an out-of-bounds write.

## Fix

### File: NewArrayComputedSizeOverflow.cpp

```cpp
#include <cstdint>
#include <cstring>
#include <limits>

// Reassembles a fragmented message from a custom binary transport protocol.
// Each fragment carries its own header and payload; headerLen and payloadLen
// are parsed directly from the fragment's wire header fields, which the
// remote peer controls.
uint8_t* ReassembleFragment(const uint8_t* headerData, uint32_t headerLen,
                             const uint8_t* payloadData, uint32_t payloadLen)
{
    // Validate that the sum of lengths does not overflow.
    // If headerLen + payloadLen would exceed the maximum value of uint32_t,
    // reject the input and return nullptr to signal failure.
    if (headerLen > std::numeric_limits<uint32_t>::max() - payloadLen) {
        return nullptr;
    }

    uint32_t totalSize = headerLen + payloadLen;

    // After validation, the allocation is safe: totalSize holds the true sum
    // without wraparound, and it equals the exact number of bytes to be copied.
    uint8_t* buffer = new uint8_t[totalSize];

    std::memcpy(buffer, headerData, headerLen);
    std::memcpy(buffer + headerLen, payloadData, payloadLen);

    return buffer;
}
```

## Explanation

The overflow check on line 16 validates that `headerLen` fits within the remaining range before addition. Equivalent to `headerLen + payloadLen <= UINT32_MAX`, this formulation avoids performing the addition itself, which would overflow.

Once this check passes, `totalSize = headerLen + payloadLen` on line 21 computes the true sum without wrapping, `new uint8_t[totalSize]` allocates exactly that many bytes, and both `memcpy` calls write within bounds.

If the sum would overflow, the function returns `nullptr` to signal failure; the caller must check for this and handle it (e.g., discard the fragment or terminate the connection).

## Behaviour changes

**Before fix:** Oversized `headerLen` and `payloadLen` pairs that wrap silently produce an undersized heap buffer, causing subsequent memory corruption.

**After fix:** Inputs that would cause overflow are rejected early, returning `nullptr` and preventing the out-of-bounds write. Callers that previously received a corrupted buffer now receive a failure signal and can handle the error safely.

