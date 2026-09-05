## Verdict

Out-of-bounds write via integer overflow in computed buffer size.

## Source

```cpp
uint32_t totalSize = headerLen + payloadLen;
uint8_t* buffer = new uint8_t[totalSize];
```

The `totalSize` calculation overflows when `headerLen` and `payloadLen` are attacker-controlled values from untrusted input (wire protocol headers). An attacker can craft values—for example, `headerLen = 0xFFFFFFF0` and `payloadLen = 0x20`—such that their sum wraps around to a small value like `0x10`. The subsequent `memcpy` operations then write far more data than the allocated buffer can hold.

## Fix

```cpp
#include <cstdint>
#include <cstring>
#include <limits>

uint8_t* ReassembleFragment(const uint8_t* headerData, uint32_t headerLen,
                             const uint8_t* payloadData, uint32_t payloadLen)
{
    // Check for integer overflow in size calculation
    if (headerLen > std::numeric_limits<uint32_t>::max() - payloadLen) {
        return nullptr;  // or throw an exception, depending on error handling policy
    }
    
    uint32_t totalSize = headerLen + payloadLen;
    
    // Optionally: enforce a reasonable upper bound on reassembled message size
    constexpr uint32_t MAX_MESSAGE_SIZE = 1024 * 1024;  // 1 MB limit
    if (totalSize > MAX_MESSAGE_SIZE) {
        return nullptr;
    }

    uint8_t* buffer = new uint8_t[totalSize];

    std::memcpy(buffer, headerData, headerLen);
    std::memcpy(buffer + headerLen, payloadData, payloadLen);

    return buffer;
}
```

## Explanation

The vulnerability arises because both `headerLen` and `payloadLen` originate from untrusted wire-format headers controlled by a remote peer. In C++, unsigned integer addition wraps silently on overflow, so `0xFFFFFFF0 + 0x20 = 0x10000010` becomes `0x10` when stored in a `uint32_t`. This causes the buffer to be allocated far too small relative to the data the subsequent `memcpy` calls attempt to write.

The fix adds an overflow check before the addition: `if (headerLen > UINT32_MAX - payloadLen)` detects whether adding these two values would exceed the maximum representable `uint32_t` value. An additional size sanity check (`MAX_MESSAGE_SIZE`) prevents excessively large allocations that might succeed but exhaust system memory or violate application protocol constraints.

The function now returns `nullptr` on overflow or oversized input, allowing the caller to detect and reject malformed fragments before any buffer operations occur.
