## Verdict

Real vulnerability confirmed.

## Source

The vulnerability originates in `write_payload()` parameters `offset` and `length`, which flow unchecked from the caller `encode_frame()` into the sink.

## Fix

Replace the incomplete bounds check with validation of both offset and the remaining capacity:

**Vulnerable code (line 6-7):**
```c
if (length > capacity) {
    return;
}
```

**Fixed code:**
```c
if (offset > capacity || length > capacity - offset) {
    return;
}
```

## Explanation

The original check validates only that `length` does not exceed `capacity` in isolation. However, CWE-787 requires validating that the write operation stays within bounds when both offset and length are combined. A caller supplying offset=250, length=10, and capacity=256 passes the original check (10 ≤ 256) but writes to bytes 250–259, overflowing a 256-byte buffer (valid indices 0–255).

The fix validates bounds in the order specified by CWE-787/c guidance: first check that `offset ≤ capacity`, then check that `length ≤ capacity - offset`. The short-circuit evaluation of `||` ensures the subtraction cannot underflow when offset exceeds capacity. This prevents writes that start before the end of the buffer and prevents writes that extend past the end.

## Behaviour changes

- Calls with offset > capacity are now rejected (previously wrote out of bounds)
- Calls with offset + length > capacity are now rejected (previously wrote out of bounds)
- Calls with valid offset and offset + length ≤ capacity proceed unchanged
