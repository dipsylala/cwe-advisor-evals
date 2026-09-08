## Verdict

exploitable

## Source

The `offset` parameter (type `int`) is passed directly from the caller to the bounds check without validation of its sign. When `offset` is negative, the cast to `size_t` in the condition produces a very large positive value due to two's complement representation, causing the bounds check to wrap around and pass when it should fail.

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
    // Validate offset is non-negative and within bounds
    if (offset < 0 || (size_t)offset > packet_len) {
        return -1;
    }
    
    // Validate length does not exceed remaining buffer and output capacity
    if (length > packet_len - (size_t)offset || length > out_capacity) {
        return -1;
    }
    
    memcpy(out, packet + offset, length);
    return (int)length;
}
```

## Explanation

The original condition `(size_t)offset + length <= packet_len` is unsafe because casting a signed `int` to `size_t` happens before the bounds check, allowing negative offsets to wrap to large positive values. The fix separates the validation into two explicit checks: first, it validates that `offset` is non-negative and does not exceed `packet_len` while the value is still signed, preventing the wrap-around. Second, it validates that `length` does not exceed the remaining buffer space (computed as `packet_len - (size_t)offset`, which is now safe because offset has been validated) and does not exceed the output capacity. This ensures both buffers are accessed only within their valid ranges.

## Behaviour changes

none

