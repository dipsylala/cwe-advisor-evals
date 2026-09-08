## Verdict
Confirmed: CWE-125 out-of-bounds read on line 42. The `field_index` extracted from untrusted network data is used to index the `descriptors` array without bounds checking. Since `field_index` is `uint8_t` (range 0-255) and `descriptors` has only 16 elements, any `field_index >= 16` causes an out-of-bounds memory read.

## Source
The vulnerability is in `resolve_field_descriptor()`, lines 32-45. The function accepts a network-supplied frame and extracts the field index at line 39:
```c
uint8_t field_index = frame[0];
```
This untrusted value is then used directly to index a fixed-size array at line 42:
```c
*out = descriptors[field_index];
```
No validation ensures `field_index` is within the bounds of `descriptors[MAX_FIELDS]`.

## Fix
### File: ArrayIndexUnvalidatedNetworkOffset.c

```c
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define MAX_FIELDS 16

/* Describes one field within a decoded frame: where its payload starts
 * and how many bytes it occupies, plus a type tag for the decoder. */
typedef struct {
    uint16_t offset;
    uint16_t length;
    uint8_t  type;
} field_descriptor_t;

/* Static table of known field layouts for this protocol version. Only
 * the first few slots are populated; the rest are zero-initialized. */
static const field_descriptor_t descriptors[MAX_FIELDS] = {
    { 0,  4, 1 },  /* sequence number */
    { 4,  4, 1 },  /* timestamp */
    { 8,  8, 2 },  /* session token */
    { 16, 2, 1 },  /* flags */
};

/*
 * Frame layout on the wire:
 *   byte 0      - field index selecting an entry in `descriptors`
 *   bytes 1..N  - remainder of the frame (unused here)
 *
 * Resolves the field index from an inbound frame to its descriptor so
 * the caller knows where and how much payload to read next.
 */
int resolve_field_descriptor(const uint8_t *frame, size_t frame_len,
                              field_descriptor_t *out)
{
    if (frame == NULL || out == NULL || frame_len < 1) {
        return -1;
    }

    uint8_t field_index = frame[0];

    /* Validate that field_index is within the bounds of the descriptors array */
    if (field_index >= MAX_FIELDS) {
        return -1;
    }

    *out = descriptors[field_index];

    return 0;
}

/*
 * Reads a frame from the connection buffer and reports the payload
 * bounds for the field it selects. Returns 0 on success, -1 on error.
 */
int handle_frame(const uint8_t *frame, size_t frame_len,
                  uint16_t *payload_offset, uint16_t *payload_length)
{
    field_descriptor_t entry;

    if (resolve_field_descriptor(frame, frame_len, &entry) != 0) {
        return -1;
    }

    *payload_offset = entry.offset;
    *payload_length = entry.length;
    return 0;
}
```

## Explanation
The fix adds a bounds check at line 41-43 (between extracting `field_index` and using it as an array index) to validate that the untrusted field index does not exceed the array size. If `field_index >= MAX_FIELDS`, the function returns an error code (-1), rejecting the malformed frame and preventing the out-of-bounds read.

This is a primary defense: it directly constrains the taint source (network-supplied field index) before it reaches the array access sink. The validation must occur before line 42 to be effective.
