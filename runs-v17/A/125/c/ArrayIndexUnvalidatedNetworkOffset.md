## Verdict

Out-of-bounds read at line 42. The `field_index` from untrusted network input is used to index into the `descriptors` array without bounds validation, allowing reads beyond the array's 16 entries.

## Source

The vulnerability exists in `resolve_field_descriptor()`. Line 39 reads the field index directly from the network frame: `uint8_t field_index = frame[0]`. Line 42 then uses this unchecked value to access `descriptors[field_index]` without verifying it is less than `MAX_FIELDS` (16).

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

    // Validate the field index is within bounds before accessing the array
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

The fix adds a bounds check immediately after reading the untrusted field index. The comparison `field_index >= MAX_FIELDS` rejects any value that would cause an out-of-bounds array access, since valid indices are 0 through 15. The function returns -1 on validation failure, signaling an error to the caller without attempting the unsafe array access. This prevents the out-of-bounds read while maintaining the existing error-handling interface.
