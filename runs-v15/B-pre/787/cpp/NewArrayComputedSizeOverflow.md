## Verdict

Exploitable. Integer overflow in the size calculation allows allocation of a buffer smaller than the data subsequently written to it.

## Source

Lines 8-9: Parameters `headerLen` and `payloadLen` are `uint32_t` values parsed directly from wire headers, controlled by the remote peer. The function comment acknowledges both as attacker-influenced fields.

## Fix

**Vulnerable Code** (lines 15-18):
```cpp
uint32_t totalSize = headerLen + payloadLen;

// SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
uint8_t* buffer = new uint8_t[totalSize];
```

**Fixed Code**:
```cpp
// Check for integer overflow in size calculation
if (headerLen > UINT32_MAX - payloadLen) {
    return nullptr;
}

uint32_t totalSize = headerLen + payloadLen;

// Validate against a reasonable maximum fragment size
const uint32_t MAX_FRAGMENT_SIZE = 0x10000000;  // 256 MB
if (totalSize > MAX_FRAGMENT_SIZE) {
    return nullptr;
}

uint8_t* buffer = new uint8_t[totalSize];
```

## Explanation

The original code computes `totalSize` as the sum of two untrusted 32-bit values with no overflow check. An attacker can supply `headerLen = 0xFFFFFFF0` and `payloadLen = 0x20`, causing the addition to wrap to `0x10`. The allocation creates a 16-byte buffer, but the subsequent `memcpy` calls write 0xFFFFFFF0 + 0x20 bytes, corrupting memory far beyond the allocation. The fix adds an explicit overflow check before the addition and a secondary validation against a reasonable maximum size, preventing undersized allocation. The caller receives `nullptr` on overflow or excessive size, allowing it to reject the malformed fragment rather than triggering the corruption.

## Behaviour changes

The return value changes: the fixed code returns `nullptr` on integer overflow or size validation failure, whereas the original code would allocate a too-small buffer and proceed to the memcpy operations. Callers must check for and handle the `nullptr` return to avoid null-pointer dereference. This is necessary and intentional—silently proceeding with a wrapped size would leave the out-of-bounds write undetected.
