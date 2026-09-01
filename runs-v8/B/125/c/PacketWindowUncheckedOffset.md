## Verdict

exploitable

## Source

Parameters `offset` (int, can be negative) and `length` (size_t, attacker-controlled) passed to `copy_packet_window()`. Data flows to the `memcpy()` call on line 13.

## Fix

**Vulnerable code:**
```c
if ((size_t)offset + length <= packet_len && length <= out_capacity) {
    memcpy(out, packet + offset, length);
    return (int)length;
}
```

**Fixed code:**
```c
if (offset >= 0 && (size_t)offset <= packet_len && 
    length <= packet_len - (size_t)offset && length <= out_capacity) {
    memcpy(out, packet + offset, length);
    return (int)length;
}
```

## Explanation

The original check casts the signed `offset` parameter to `size_t` before validation. When `offset` is negative (e.g., -1), this cast converts it to SIZE_MAX, and the subsequent arithmetic `SIZE_MAX + length` overflows and wraps back to a small value, allowing the check to pass. The pointer arithmetic `packet + offset` then reads from memory far before the buffer. The fixed check validates `offset >= 0` while still signed, then checks that the offset and length both fit within the packet buffer using unsigned subtraction to prevent underflow. This ensures the memcpy reads only from allocated bytes within the packet.

## Behaviour changes

none
