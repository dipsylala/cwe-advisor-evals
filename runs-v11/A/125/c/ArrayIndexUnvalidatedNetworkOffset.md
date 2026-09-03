## Verdict
The vulnerability is confirmed. The `field_index` value read directly from untrusted network data (frame[0]) is used without bounds validation to index into the `descriptors` array, enabling an out-of-bounds read.

## Source
Line 39-42:
```c
uint8_t field_index = frame[0];

// SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
*out = descriptors[field_index];
```

The attacker controls the network frame contents. A malicious frame with `field_index` >= 16 (or any value beyond the 4 initialized entries) causes the code to read uninitialized or out-of-bounds memory from the `descriptors` static array.

## Fix
Add a bounds check before indexing the array:

```c
int resolve_field_descriptor(const uint8_t *frame, size_t frame_len,
                              field_descriptor_t *out)
{
    if (frame == NULL || out == NULL || frame_len < 1) {
        return -1;
    }

    uint8_t field_index = frame[0];

    if (field_index >= MAX_FIELDS) {
        return -1;
    }

    *out = descriptors[field_index];

    return 0;
}
```

## Explanation
The fix adds a check `if (field_index >= MAX_FIELDS)` before using `field_index` to index the array. This prevents any value outside the valid range [0, MAX_FIELDS - 1] from being used as an array subscript.

While only 4 descriptors are explicitly initialized in the static array, reading beyond the initialized portion but within the allocated array still constitutes undefined behavior and a potential information leak. The bounds check rejects all out-of-bounds attempts, regardless of whether the out-of-bounds read would happen to access allocated but uninitialized memory or genuine memory beyond the array.

The fix returns -1 (error) when the field index is invalid, consistent with other error conditions in the function and allowing the caller to reject malformed frames.
