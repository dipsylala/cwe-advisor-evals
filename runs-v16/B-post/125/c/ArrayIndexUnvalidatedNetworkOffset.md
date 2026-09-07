## Verdict

Confirmed. Out-of-bounds read at line 42: `field_index` is read from untrusted network input (frame[0]) without validation, then used directly to index the `descriptors` array. Since `field_index` is `uint8_t` (0–255) and `descriptors` has only `MAX_FIELDS = 16` entries, any value ≥ 16 causes an out-of-bounds read.

## Source

Network-supplied frame data. The function `resolve_field_descriptor()` receives a frame pointer (described as frame layout from the wire), reads byte 0 as a field index, and passes it directly to array indexing without bounds validation.

Data path:
- `frame` (untrusted, from network)
- `frame[0]` → `field_index` (uint8_t, can be 0–255)
- `field_index` → `descriptors[field_index]` (array has 16 elements)
- Sink: line 42, array access without bounds check

## Fix

```c
int resolve_field_descriptor(const uint8_t *frame, size_t frame_len,
                              field_descriptor_t *out)
{
    if (frame == NULL || out == NULL || frame_len < 1) {
        return -1;
    }

    uint8_t field_index = frame[0];

    // Validate index against array bounds before accessing
    if (field_index >= MAX_FIELDS) {
        return -1;
    }

    *out = descriptors[field_index];

    return 0;
}
```

## Explanation

The fix adds an explicit bounds check immediately before the array access. When `field_index >= MAX_FIELDS`, the function returns -1 (error), consistent with the existing error handling contract. This prevents any out-of-bounds read access to the `descriptors` array. The check is placed at the point of the sink (just before line 42) and validates against the known array size. No attacker-controlled value is used downstream of the check. The function's contract is preserved: it returns 0 with a populated descriptor on success, or -1 on any error (null pointers, short frame, or invalid index).

## Behaviour changes

- Invalid field indices (≥ 16) now return -1 (error) instead of reading out-of-bounds and returning success with uninitialized or out-of-range data.
- Callers must check the return value and handle the error case; the payload offset and length are not populated when the index is invalid, so downstream code that does not check the return value will process stale or zero-initialized output from a prior call. This is safer than the previous behaviour (silent out-of-bounds read) but requires proper error handling at the call site.
