## Verdict
Confirmed. Integer overflow in the summation of attacker-controlled uint32_t values causes undersized buffer allocation.

## Source
Lines 15–18: `headerLen` and `payloadLen` are untrusted wire format fields. Their sum on line 15 can wrap; a pair such as (0xFFFFFFF0, 0x20) yields 0x10 instead of the intended 0x100000010. The allocation on line 18 reserves only the wrapped value, but the memcpy operations on lines 20–21 attempt to copy the full, much larger amounts, writing past the buffer boundary.

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
    // Validate that the sum of lengths does not overflow a uint32_t.
    // This prevents an attacker from crafting two large values that wrap
    // around to a small result, causing an undersized allocation followed
    // by out-of-bounds writes in the memcpy calls below.
    if (headerLen > std::numeric_limits<uint32_t>::max() - payloadLen) {
        return nullptr;
    }

    uint32_t totalSize = headerLen + payloadLen;

    uint8_t* buffer = new uint8_t[totalSize];

    std::memcpy(buffer, headerData, headerLen);
    std::memcpy(buffer + headerLen, payloadData, payloadLen);

    return buffer;
}
```

## Explanation
The fix validates that `headerLen` does not exceed the maximum value minus `payloadLen` before the addition occurs. This ensures the sum cannot wrap. If overflow is detected (meaning the sum would exceed uint32_t range), the function returns nullptr immediately rather than allocating a buffer that is too small. This closes the window during which an attacker's addition wraps to a tiny value, preventing the subsequent out-of-bounds writes via memcpy.
