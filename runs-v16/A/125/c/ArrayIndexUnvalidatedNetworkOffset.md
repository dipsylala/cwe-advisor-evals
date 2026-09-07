## Verdict

Confirmed. The code reads from the `descriptors` array at an untrusted index without validating that the index is within bounds, resulting in an out-of-bounds read.

## Source

```c
int resolve_field_descriptor(const uint8_t *frame, size_t frame_len,
                              field_descriptor_t *out)
{
    if (frame == NULL || out == NULL || frame_len < 1) {
        return -1;
    }

    uint8_t field_index = frame[0];

    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    *out = descriptors[field_index];  // Line 42: field_index may exceed MAX_FIELDS

    return 0;
}
```

## Fix

```c
int resolve_field_descriptor(const uint8_t *frame, size_t frame_len,
                              field_descriptor_t *out)
{
    if (frame == NULL || out == NULL || frame_len < 1) {
        return -1;
    }

    uint8_t field_index = frame[0];

    // Validate field_index is within bounds before array access
    if (field_index >= MAX_FIELDS) {
        return -1;
    }

    *out = descriptors[field_index];

    return 0;
}
```

## Explanation

The vulnerability occurs because `field_index` is derived directly from untrusted network data (`frame[0]`) and used as an array index without validation. Since `field_index` is a `uint8_t`, it can hold values from 0 to 255, but the `descriptors` array only contains `MAX_FIELDS` (16) elements. An attacker can craft a frame with a `field_index` value >= 16 to read memory beyond the array bounds, potentially leaking sensitive information.

The fix adds a bounds check that rejects any `field_index` value that is greater than or equal to `MAX_FIELDS`, preventing the out-of-bounds read and treating invalid indices as errors (return -1).
