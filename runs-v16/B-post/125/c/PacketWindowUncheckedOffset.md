## Verdict

exploitable

## Source

The `offset` parameter (line 6, declared as `int`) receives untrusted input to the `copy_packet_window()` function. This value is not validated for sign before being used in pointer arithmetic.

## Fix

**Vulnerable code (line 11-13):**
```c
if ((size_t)offset + length <= packet_len && length <= out_capacity) {
    // Line 13: memcpy reads from packet + offset without sign validation
    memcpy(out, packet + offset, length);
```

**Fixed code:**
```c
if (offset >= 0 && (size_t)offset + length <= packet_len && length <= out_capacity) {
    memcpy(out, packet + offset, length);
```

## Explanation

The original bounds check on line 11 casts `offset` to `size_t` (unsigned) after the value is already interpreted as a signed integer. When `offset` is negative (e.g., -1), the cast to `size_t` produces a very large unsigned value (SIZE_MAX), which can cause the addition to wrap around and bypass the bounds check. A negative offset should be rejected immediately while the value is still signed, before any conversion to unsigned. The fix adds an explicit `offset >= 0` check that runs before the problematic cast, ensuring negative offsets are rejected and the pointer arithmetic `packet + offset` cannot read from before the buffer's start.

## Behaviour changes

none

The fixed function preserves all existing behaviour: same parameters, same return type, same success/failure semantics. The only change is the addition of a sign check that prevents exploitation of the casting vulnerability—the check fails for negative offsets (returning -1) rather than allowing them to bypass validation and trigger an out-of-bounds read.
