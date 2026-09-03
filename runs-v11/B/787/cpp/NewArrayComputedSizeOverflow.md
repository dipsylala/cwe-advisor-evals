## Verdict

**CONFIRMED.** Integer overflow in size calculation allows attacker-controlled `headerLen` and `payloadLen` to underflow `totalSize`, causing `new[]` to allocate a buffer smaller than the data written into it via `memcpy()`.

## Source

Wire-supplied `headerLen` and `payloadLen` (lines 8–9, 15) are 32-bit values with no prior validation. Their sum on line 15 can overflow: e.g., 0xFFFFFFF0 + 0x20 wraps to 0x10, allocating 16 bytes where 0x100000010 are written (lines 20–21).

## Fix

Replace raw buffer management with a container that owns its storage and validates allocation, and explicitly check for overflow before accepting the sizes:

```cpp
#include <cstdint>
#include <cstring>
#include <vector>
#include <stdexcept>

uint8_t* ReassembleFragment(const uint8_t* headerData, uint32_t headerLen,
                             const uint8_t* payloadData, uint32_t payloadLen)
{
    // Detect integer overflow before allocation.
    // If headerLen + payloadLen would overflow, reject it.
    const uint32_t MAX_SIZE = UINT32_MAX; // or a application-specific limit
    if (headerLen > MAX_SIZE - payloadLen) {
        throw std::overflow_error("Fragment size exceeds maximum");
    }
    
    uint32_t totalSize = headerLen + payloadLen;
    
    // Use std::vector to own the buffer and prevent out-of-bounds access.
    std::vector<uint8_t> buffer(totalSize);
    
    // memcpy is safe because totalSize is now validated and buffer owns totalSize bytes.
    if (headerLen > 0) {
        std::memcpy(buffer.data(), headerData, headerLen);
    }
    if (payloadLen > 0) {
        std::memcpy(buffer.data() + headerLen, payloadData, payloadLen);
    }
    
    // Return ownership to caller (caller is responsible for deallocation).
    // For a more modern fix, return std::vector<uint8_t> instead.
    uint8_t* result = new uint8_t[totalSize];
    std::memcpy(result, buffer.data(), totalSize);
    return result;
}
```

**Preferred modern fix (returns a container):**

```cpp
#include <cstdint>
#include <cstring>
#include <vector>
#include <stdexcept>

std::vector<uint8_t> ReassembleFragment(const uint8_t* headerData, uint32_t headerLen,
                                         const uint8_t* payloadData, uint32_t payloadLen)
{
    // Detect integer overflow before allocation.
    const uint32_t MAX_SIZE = UINT32_MAX; // or application-specific limit
    if (headerLen > MAX_SIZE - payloadLen) {
        throw std::overflow_error("Fragment size exceeds maximum");
    }
    
    uint32_t totalSize = headerLen + payloadLen;
    std::vector<uint8_t> buffer(totalSize);
    
    if (headerLen > 0) {
        std::memcpy(buffer.data(), headerData, headerLen);
    }
    if (payloadLen > 0) {
        std::memcpy(buffer.data() + headerLen, payloadData, payloadLen);
    }
    
    return buffer;
}
```

## Explanation

The original code computes `totalSize` without checking for integer overflow. When `headerLen` and `payloadLen` sum to a value exceeding 2^32 – 1, the result wraps silently to a small value. The undersized buffer is then passed to `memcpy()`, which writes the full (attacker-specified) lengths into memory it does not own.

The fix addresses this in two ways:

1. **Overflow detection**: Before computing `totalSize`, verify that `headerLen <= UINT32_MAX - payloadLen`. If the check fails, reject the input and throw an exception, which the caller must handle.

2. **Safe container**: Use `std::vector<uint8_t>` to allocate and own the buffer. This inversion of responsibility makes it the container's job to enforce its own capacity and prevents accidental out-of-bounds writes through stray pointer arithmetic. The vector owns exactly `totalSize` bytes and will not grow unless the code calls `.resize()` or `.push_back()`.

The preferred approach returns `std::vector` instead of a raw pointer, eliminating the caller's burden to deallocate and making the ownership contract explicit at the function signature level.

## Behaviour changes

- **Input rejection**: Fragments with `headerLen + payloadLen > UINT32_MAX` are now rejected with an exception instead of silently allocated as undersized buffers.
- **Caller responsibility**: If returning a raw pointer (first fix), the caller must now handle `std::overflow_error`. If returning `std::vector` (preferred fix), the caller receives an empty/partial vector and must check the exception.
- **Memory safety**: All buffer writes are now guaranteed to stay within the allocated bounds; `memcpy()` can no longer write outside the vector's capacity.
- **API change (preferred fix only)**: The function signature changes from returning `uint8_t*` to `std::vector<uint8_t>`, which requires the caller to adapt. This is a necessary change to eliminate manual memory management and make the ownership explicit.
