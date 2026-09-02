## Verdict

exploitable

## Source

The `offset` parameter (signed `int`, line 6) is untrusted input from the caller. When passed as a negative value (e.g., -1), it is cast to unsigned `size_t` in the bounds check before the sign is validated, causing wraparound to a very large positive value.

## Fix

**Vulnerable code (line 11):**
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

The vulnerability occurs because the original bounds check casts `offset` from signed `int` to unsigned `size_t` before validating it. When `offset` is negative (e.g., -1), the cast converts it to a very large positive value (`SIZE_MAX`). The arithmetic `(size_t)(-1) + length` then wraps around within the unsigned range, potentially passing the check `<= packet_len` when it should fail. This allows `memcpy()` to read from memory before the packet buffer.

The fix adds three defensive checks in the correct order: (1) `offset >= 0` validates the sign while `offset` is still signed, before any conversion or arithmetic; (2) `(size_t)offset <= packet_len` ensures the offset is within the buffer's bounds; (3) `length <= packet_len - (size_t)offset` ensures the offset plus length does not exceed the buffer without underflow. This follows the guidance to "test the sign while the value is still signed" and to "validate `offset <= buffer_size` first, then `length <= buffer_size - offset`, in that order, so the subtraction cannot underflow."

## Behaviour changes

The condition now rejects negative offsets with a check that evaluates to false, causing the function to return -1 instead of attempting the copy. This is the intended security fix; negative offsets are invalid and should be rejected. The function's return contract remains unchanged: it still returns the length copied on success and -1 on validation failure.
