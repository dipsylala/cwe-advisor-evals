## Verdict

exploitable

## Source

Function parameters `headerLen` and `payloadLen` (uint32_t) derived from attacker-controlled wire protocol data, per the code comment: "Both lengths are attacker-influenced 32-bit fields taken straight off the wire".

## Fix

**Vulnerable code (line 15-21):**

```cpp
uint32_t totalSize = headerLen + payloadLen;

// SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
uint8_t* buffer = new uint8_t[totalSize];

std::memcpy(buffer, headerData, headerLen);
std::memcpy(buffer + headerLen, payloadData, payloadLen);

return buffer;
```

The vulnerability occurs because the addition `headerLen + payloadLen` can overflow when both are large (e.g., 0xFFFFFFF0 + 0x20 = 0x10), resulting in under-allocation before the memcpy operations proceed with the original, unvalidated lengths.

**Fixed code:**

```cpp
// Validate that headerLen + payloadLen doesn't overflow
// If payloadLen > UINT32_MAX - headerLen, the addition would wrap around
if (payloadLen > UINT32_MAX - headerLen) {
    throw std::overflow_error("Fragment size overflows uint32_t");
}

uint32_t totalSize = headerLen + payloadLen;

// Use vector for safe allocation with automatic bounds tracking
std::vector<uint8_t> buffer(totalSize);

std::memcpy(buffer.data(), headerData, headerLen);
std::memcpy(buffer.data() + headerLen, payloadData, payloadLen);

return buffer;
```

## Explanation

The fix validates the sum before computing it by checking if `payloadLen > UINT32_MAX - headerLen`—this computed check cannot itself overflow. It then replaces the raw `new[]` allocation with `std::vector<uint8_t>`, which owns its storage and tracks its capacity automatically. The vector's `.data()` method replaces raw pointer arithmetic, and the function now returns the vector by value rather than a raw owning pointer. This prevents integer overflow and eliminates the buffer-size mismatch: the memcpy operations now write into a buffer guaranteed to be at least `totalSize` bytes, and any attempt to write beyond that would be caught by address sanitizers or runtime hardening. The overflow check uses a safe comparison that does not itself overflow.

## Behaviour changes

**Return type changed from `uint8_t*` to `std::vector<uint8_t>`**: The original interface required the caller to manually manage the returned pointer's lifetime (call `delete[]`). This interface change is necessary because (1) the C++ guidance prescribes that containers own their own storage, (2) returning a raw pointer to vector's internal data after the function returns would produce a dangling pointer, and (3) `std::vector` return-by-value is idiomatic C++23 with move semantics, eliminating the copy overhead. Callers must change from `uint8_t* ptr = ReassembleFragment(...); ... delete[] ptr;` to `auto buffer = ReassembleFragment(...);` and treat it as a value.

**Exception thrown on integer overflow**: The original code silently allowed the overflow to wrap, leading to undefined behaviour and exploitable out-of-bounds writes. The fixed code throws `std::overflow_error`, signalling to the caller that the input is invalid and cannot be processed. This is the correct failure mode per the CWE-787 guidance: "Report a refused write to the caller rather than only logging it".

**Added `#include <vector>` and `#include <stdexcept>`**: Required for `std::vector<uint8_t>` and `std::overflow_error`.
