## Verdict

EXPLOITABLE. The vulnerability is real and easily triggered by network input.

## Source

Line 39: `uint8_t field_index = frame[0];` - untrusted network input read directly from the first byte of an inbound frame. The `frame` parameter originates from network data and is not validated before use.

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

The vulnerability occurs because `field_index` is read from untrusted network data (`frame[0]`) and used to index directly into the `descriptors` array, which has only `MAX_FIELDS` (16) elements. A uint8_t can hold values 0-255, so any input byte >= 16 will read past the end of the array.

The fix adds an explicit bounds check immediately before the array access. It validates that `field_index < MAX_FIELDS`, returning -1 if the check fails. This prevents out-of-bounds reads by rejecting indices that exceed the array's allocated size. The check happens at the sink (the actual array access) in the same function that performs it, as prescribed by CWE-125 guidance. The error path mirrors the existing validation at the function's entry point, maintaining consistent error handling.

## Behaviour changes

**Functional impact:** Frames that select an uninitialized field index (byte value >= 16) now return an error instead of reading undefined memory. Callers that receive -1 must treat this as a frame format error.

**Security impact:** Out-of-bounds reads over the `descriptors` array are eliminated. An attacker can no longer trigger information disclosure by crafting a frame with a large field index.

**Return value:** The function now returns -1 for invalid field indices, consistent with the existing error handling for NULL pointers or undersized frames. Callers already check the return value, so no changes are needed upstream.
