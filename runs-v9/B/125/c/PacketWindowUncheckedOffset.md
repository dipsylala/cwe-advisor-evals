## Verdict

exploitable (confidence: high)

## Source

`copy_packet_window`'s parameters `offset` (signed `int`) and `length` (`size_t`) are the untrusted inputs; both are attacker-influenced values describing a window into the `packet` buffer, and neither is validated before they drive the bounds check.

## Fix

Vulnerable code (`PacketWindowUncheckedOffset.c`, line 11-14):

```c
if ((size_t)offset + length <= packet_len && length <= out_capacity) {
    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    memcpy(out, packet + offset, length);
    return (int)length;
}
```

Fixed code:

```c
if (offset < 0) {
    return -1;
}

size_t uoffset = (size_t)offset;

if (uoffset > packet_len || length > packet_len - uoffset || length > out_capacity) {
    return -1;
}

memcpy(out, packet + uoffset, length);
return (int)length;
```

## Explanation

The original check converts `offset` to `size_t` before testing its sign. A negative `offset` (e.g. `-1`) becomes a huge unsigned value (`SIZE_MAX` for `-1`); adding `length` to it wraps around modulo `SIZE_MAX+1` and can land back at or below `packet_len`, so the check passes even though the real offset is negative. `memcpy(out, packet + offset, length)` then computes `packet - 1` (or further back), reading memory before the start of the buffer - an out-of-bounds read. A large, non-overflowing `length` combined with a large `offset` can trigger the same wraparound in the forward direction. The fix rejects a negative `offset` while it is still a signed value, then performs the bounds check with a subtraction (`length > packet_len - uoffset`) instead of an addition, which cannot itself overflow once `uoffset <= packet_len` is already established. `out_capacity` is still checked as before, so the destination-side bound is unchanged.

## Behaviour changes

- `copy_packet_window` now returns `-1` for a negative `offset` instead of potentially performing an out-of-bounds `memcpy` and returning a positive length with garbage data copied into `out`. This is the security fix itself - previously undefined/unsafe behaviour becomes a defined rejection - not an unrelated behaviour change.
- All other cases (non-negative `offset` within bounds, or any input that legitimately fails the original bound checks) return the same values as before: the copied length on success, `-1` on failure.
- No change to function signature, argument usage, or the destination-capacity check (`length <= out_capacity`).
