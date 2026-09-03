## Verdict
exploitable

## Source
Function parameters `offset` (signed int) and `length` (size_t) received from caller without validation. `offset` can be negative; `length` is untrusted.

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
// Reject negative offsets before any conversion to unsigned type
if (offset < 0) {
    return -1;
}

size_t safe_offset = (size_t)offset;

// Validate offset and length against packet bounds
if (safe_offset > packet_len || length > packet_len - safe_offset) {
    return -1;
}

// Validate length against output capacity
if (length > out_capacity) {
    return -1;
}

memcpy(out, packet + safe_offset, length);
return (int)length;
```

## Explanation
The original bounds check `(size_t)offset + length <= packet_len` casts the signed `offset` to `size_t` (unsigned) before validation. If `offset` is negative, this produces a very large positive value, causing the addition to wrap back into range and the bounds check to pass incorrectly. The fix rejects negative offsets first, while the value is still signed, then performs overflow-safe bounds checking by testing `offset <= packet_len` and `length <= packet_len - offset` separately, preventing underflow in the subtraction. This ensures the pointer arithmetic `packet + safe_offset` cannot read before the packet buffer.

## Behaviour changes
The function now rejects three additional error cases compared to the original:
- Negative offset values (now returns -1 instead of attempting the operation)
- Cases where offset exceeds packet_len (now returns -1 instead of potentially succeeding with the unsafe check)
- Cases where offset + length exceeds packet_len via underflow-safe subtraction

All three represent malformed input that should not reach the memcpy sink. The sink contract is preserved: the function still returns the length on success and -1 on any error condition, with no change to callers' handling logic.
