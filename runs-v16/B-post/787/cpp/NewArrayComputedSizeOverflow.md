## Verdict

CONFIRMED. Integer overflow in size calculation (line 15) leads to under-allocation, followed by out-of-bounds writes via `memcpy()` (lines 20-21).

## Source

`headerLen` and `payloadLen` parameters are attacker-controlled 32-bit values from the wire protocol. Their sum can overflow silently: `uint32_t totalSize = headerLen + payloadLen` wraps when `headerLen + payloadLen > UINT32_MAX` (e.g., `0xFFFFFFF0 + 0x20 = 0x10`).

## Fix

```cpp
#include <cstdint>
#include <cstring>
#include <vector>
#include <stdexcept>

uint8_t* ReassembleFragment(const uint8_t* headerData, uint32_t headerLen,
                             const uint8_t* payloadData, uint32_t payloadLen)
{
    // Validate that the sum does not overflow before allocation.
    if (headerLen > UINT32_MAX - payloadLen) {
        throw std::overflow_error("Fragment size calculation overflows");
    }
    
    uint32_t totalSize = headerLen + payloadLen;
    
    // Use std::vector for bounds-safe memory management.
    std::vector<uint8_t> buffer(totalSize);
    
    // Copy with explicit bounds: vector enforces the allocation size.
    std::memcpy(buffer.data(), headerData, headerLen);
    std::memcpy(buffer.data() + headerLen, payloadData, payloadLen);
    
    // Transfer ownership to caller via heap allocation.
    uint8_t* result = new uint8_t[totalSize];
    std::memcpy(result, buffer.data(), totalSize);
    return result;
}
```

## Explanation

The fix adds an overflow check before the size calculation and uses `std::vector` as an intermediate buffer with automatic bounds tracking. The check `headerLen > UINT32_MAX - payloadLen` detects overflow without itself overflowing. The `std::vector` ensures the allocation is exactly `totalSize` bytes, and `buffer.data()` provides a raw pointer for `memcpy()` without losing bounds information internally. After validating and assembling the data safely into the vector, the result is transferred to a heap-allocated buffer matching the original function signature. If overflow is detected, the function now rejects the malformed input by throwing an exception rather than silently producing an under-allocated buffer.

## Behaviour changes

- The function now throws `std::overflow_error` if `headerLen + payloadLen` overflows, rejecting malformed input instead of silently proceeding with corrupted size.
- Return type and ownership model are preserved: the caller still receives a heap-allocated buffer and is responsible for calling `delete[]`.
- All valid inputs (non-overflowing sums within the 32-bit range) produce identical output.
- Performance: intermediate `std::vector` allocation adds a small overhead, which is acceptable given the safety gain; the final heap allocation can be optimized later if profiling shows it matters.
