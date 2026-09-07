## Verdict

The finding is confirmed. The bounds check on line 11 casts `offset` to `size_t` before validating its sign, allowing a negative offset to wrap to a large unsigned value, overflow the bounds-check arithmetic, and pass the validation while performing an out-of-bounds read.

## Source

**File**: `PacketWindowUncheckedOffset.c`  
**Line**: 11 (bounds check) and 13 (sink)  
**Vulnerable code**:
```c
if ((size_t)offset + length <= packet_len && length <= out_capacity) {
    memcpy(out, packet + offset, length);
```

**Data flow**: The `offset` parameter (signed `int`) originates from the function caller. The bounds check converts it to `size_t` before the sign is validated, causing negative values to become large unsigned integers via two's-complement wraparound. A negative offset then causes the pointer arithmetic `packet + offset` to read before the allocated buffer.

**Exploitable scenario**: If a caller provides `offset = -1` and `length` is a small positive value that fits within the destination buffer, the check `(size_t)(-1) + length <= packet_len` evaluates to `(SIZE_MAX + length) <= packet_len`. Due to unsigned wraparound, this sum becomes a small value, the check passes, and `memcpy` reads from `packet - 1`, one byte before the start of the packet buffer.

## Fix

### File: PacketWindowUncheckedOffset.c

```c
#include <stddef.h>
#include <string.h>

int copy_packet_window(const unsigned char *packet,
                       size_t packet_len,
                       int offset,
                       size_t length,
                       unsigned char *out,
                       size_t out_capacity)
{
    // Reject negative offsets before any unsigned conversion to prevent wraparound
    if (offset < 0) {
        return -1;
    }
    
    size_t safe_offset = (size_t)offset;
    
    // Validate bounds in correct order: check offset first, then remaining space,
    // so the subtraction cannot underflow and addition cannot overflow
    if (safe_offset <= packet_len && 
        length <= packet_len - safe_offset && 
        length <= out_capacity) {
        memcpy(out, packet + safe_offset, length);
        return (int)length;
    }

    return -1;
}
```

## Explanation

The fix adds an explicit sign check while `offset` is still a signed integer, rejecting negative values before any conversion to `size_t`. This prevents two's-complement wraparound that would convert a negative offset into a large unsigned value.

The fix then restructures the bounds check to validate in the correct order: first checking that `safe_offset <= packet_len`, then checking that `length <= packet_len - safe_offset`. This order ensures the subtraction cannot underflow (because we know `safe_offset <= packet_len`), and the arithmetic cannot overflow. The original check risked overflow in the addition `(size_t)offset + length` if both operands were large.

The fix preserves the return values and error behaviour of the original: it returns the copied length on success, or -1 on error. The function still correctly validates that the requested region is available in both the source and destination buffers before copying.

## Behaviour changes

**Visible changes**: Calls with a negative `offset` now return -1 instead of potentially copying from before the packet buffer.

**No change for valid inputs**: Calls with a valid non-negative offset within `[0, packet_len)` behave identically to the original.

**Denial of service prevention**: An attacker can no longer craft a negative offset to bypass the bounds check and trigger a read-before-buffer condition. The fix constrains the offset to non-negative values before performing any arithmetic.
