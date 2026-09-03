## Verdict

Confirmed. An out-of-bounds read occurs when a field index from untrusted network input is used to access an array without bounds validation.

## Source

**Location:** Line 39-42
**Source:** `uint8_t field_index = frame[0];` - untrusted network input
**Sink:** `*out = descriptors[field_index];` - array access without bounds check
**Data Flow:** The field index is extracted directly from the first byte of a network frame and used as an array index into the `descriptors` array, which has only 16 elements (MAX_FIELDS). A uint8_t can hold values 0-255, so any value ≥ 16 reads past the array's allocated bounds.

## Fix

```c
int resolve_field_descriptor(const uint8_t *frame, size_t frame_len,
                              field_descriptor_t *out)
{
    if (frame == NULL || out == NULL || frame_len < 1) {
        return -1;
    }

    uint8_t field_index = frame[0];

    // Validate that field_index is within bounds before array access
    if (field_index >= MAX_FIELDS) {
        return -1;
    }

    *out = descriptors[field_index];

    return 0;
}
```

## Explanation

The fix adds an explicit bounds check immediately before the array access. The validation `field_index >= MAX_FIELDS` ensures that only valid indices (0-15) are used to access the `descriptors` array. If the network-supplied index is out of range, the function returns an error code (-1) instead of performing the out-of-bounds read. This follows CWE-125 guidance: validate the index against the buffer's known bound immediately before the dereference, not in a distant caller, and handle the error case explicitly.

## Behaviour changes

**Before:** The function accepted any uint8_t value as a field index and performed an array access that reads from memory beyond the 16-element array's allocation when the index ≥ 16.

**After:** The function validates that the field index is in the valid range [0, 15]. If the index is outside this range, the function returns -1 to signal an error to the caller, and the out-of-bounds read does not occur. Callers must check the return value to detect this error condition. Valid indices (0-15) behave identically before and after the fix.
