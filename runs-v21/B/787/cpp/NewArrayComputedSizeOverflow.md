## Verdict

Exploitable. The function receives attacker-controlled `headerLen` and `payloadLen` from the wire protocol. The addition at line 15 can overflow a uint32_t: for example, `headerLen = 0xFFFFFFF0` and `payloadLen = 0x20` sum to `0x100000010`, which truncates to `0x10` when stored in uint32_t. This undersized buffer is allocated at line 18, and the subsequent memcpy operations at lines 20-21 then write the full untruncated sizes into the buffer, causing out-of-bounds heap write.

## Source

Wire-protocol fields `headerLen` and `payloadLen` (lines 8-9), passed directly from the remote peer without validation. The comments in the code explicitly state these are attacker-influenced.

## Fix

### File: NewArrayComputedSizeOverflow.cpp

```cpp
#include <cstdint>
#include <cstring>
#include <stdexcept>

// Reassembles a fragmented message from a custom binary transport protocol.
// Each fragment carries its own header and payload; headerLen and payloadLen
// are parsed directly from the fragment's wire header fields, which the
// remote peer controls.
uint8_t* ReassembleFragment(const uint8_t* headerData, uint32_t headerLen,
                             const uint8_t* payloadData, uint32_t payloadLen)
{
    // Validate that headerLen + payloadLen does not overflow uint32_t.
    // If the sum would exceed the maximum representable value, reject the request.
    if (headerLen > UINT32_MAX - payloadLen) {
        throw std::overflow_error("Fragment size computation overflow");
    }
    
    uint32_t totalSize = headerLen + payloadLen;

    uint8_t* buffer = new uint8_t[totalSize];

    std::memcpy(buffer, headerData, headerLen);
    std::memcpy(buffer + headerLen, payloadData, payloadLen);

    return buffer;
}
```

## Explanation

The fix adds an overflow check before the size calculation. The condition `headerLen > UINT32_MAX - payloadLen` is mathematically equivalent to checking whether `headerLen + payloadLen` would overflow uint32_t, but computes it in a way that cannot itself overflow (because subtraction of positive uint32_t values stays within uint32_t). If the check detects that the sum would overflow, the function throws `std::overflow_error`, which prevents allocation of an undersized buffer and the subsequent out-of-bounds write. The memcpy operations now write into a buffer whose size was validated to not underflow, eliminating the CWE-787 vulnerability.

## Behaviour changes

1. **Exception on overflow**: The function now throws `std::overflow_error` when `headerLen + payloadLen` would overflow uint32_t. Previously, this case would silently allocate an undersized buffer and corrupt heap memory. Callers must now handle this exception or allow it to propagate.

2. **Include added**: `#include <stdexcept>` was added to support `std::overflow_error`.

3. **No other changes**: The allocation mechanism, memcpy operations, and return value remain structurally identical. The caller still receives a raw heap-allocated pointer and retains responsibility for freeing it.
