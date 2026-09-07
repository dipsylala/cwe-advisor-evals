## Verdict

Fixable. The integer overflow in computing `totalSize` can be prevented with overflow validation before the allocation and copy operations.

## Source

```cpp
uint32_t totalSize = headerLen + payloadLen;

// SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
uint8_t* buffer = new uint8_t[totalSize];

std::memcpy(buffer, headerData, headerLen);
std::memcpy(buffer + headerLen, payloadData, payloadLen);
```

The vulnerability: `headerLen` and `payloadLen` are attacker-controlled 32-bit values. When their sum overflows (e.g., `0xFFFFFFF0 + 0x20 = 0x10`), a small buffer is allocated. The subsequent `memcpy` calls then write far more data than the buffer can hold, corrupting memory.

## Fix

### File: NewArrayComputedSizeOverflow.cpp

```cpp
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <limits>

// Reassembles a fragmented message from a custom binary transport protocol.
// Each fragment carries its own header and payload; headerLen and payloadLen
// are parsed directly from the fragment's wire header fields, which the
// remote peer controls.
uint8_t* ReassembleFragment(const uint8_t* headerData, uint32_t headerLen,
                             const uint8_t* payloadData, uint32_t payloadLen)
{
    // Both lengths are attacker-influenced 32-bit fields taken straight off
    // the wire, so their sum can wrap around before it is ever validated.
    // A large-enough pair (e.g. headerLen = 0xFFFFFFF0, payloadLen = 0x20)
    // wraps totalSize down to 0x10, far smaller than either input.
    
    // Validate that adding the lengths would not overflow.
    if (headerLen > std::numeric_limits<uint32_t>::max() - payloadLen) {
        throw std::overflow_error("Fragment sizes exceed maximum allocation size");
    }
    
    uint32_t totalSize = headerLen + payloadLen;

    // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
    uint8_t* buffer = new uint8_t[totalSize];

    std::memcpy(buffer, headerData, headerLen);
    std::memcpy(buffer + headerLen, payloadData, payloadLen);

    return buffer;
}
```

## Explanation

The fix prevents integer overflow by validating that `headerLen + payloadLen` will not wrap around before performing the addition. The check `headerLen > std::numeric_limits<uint32_t>::max() - payloadLen` is logically equivalent to checking whether the addition would overflow: if `headerLen` is larger than the remaining space in a uint32_t after accounting for `payloadLen`, the sum would overflow.

When an overflow condition is detected, the function throws `std::overflow_error`, rejecting the invalid input. This prevents allocation of an undersized buffer and eliminates the out-of-bounds write vulnerability. The attacker cannot construct a fragment pair that passes validation without supplying reasonable, non-wrapping sizes.
