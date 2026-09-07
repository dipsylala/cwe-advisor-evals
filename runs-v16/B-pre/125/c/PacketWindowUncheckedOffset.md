## Verdict
exploitable

## Source
`offset` parameter (signed `int`, declared at line 6)

## Fix

**Vulnerable code:**
```c
if ((size_t)offset + length <= packet_len && length <= out_capacity) {
    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    memcpy(out, packet + offset, length);
    return (int)length;
}
```

**Fixed code:**
```c
if (offset >= 0 && (size_t)offset + length <= packet_len && length <= out_capacity) {
    memcpy(out, packet + offset, length);
    return (int)length;
}
```

## Explanation
The bounds check cast `offset` to `size_t` after the arithmetic operation, allowing a negative offset to become SIZE_MAX and wrap the sum back into range, bypassing the check. The fix validates that `offset >= 0` while it is still signed (before any conversion to unsigned), preventing negative values from bypassing the bounds check. This follows the C-specific guidance: "Test the sign while the value is still signed." After this check, the cast to `size_t` is safe because the offset is guaranteed non-negative, and the arithmetic cannot wrap unexpectedly.

## Behaviour changes
none
