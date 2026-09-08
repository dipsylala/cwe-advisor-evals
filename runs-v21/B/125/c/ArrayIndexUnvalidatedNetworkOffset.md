## Verdict

exploitable

## Source

`frame[0]` - an attacker-controlled byte from an inbound network frame. The byte is read directly at line 39 and used as an array index without validation.

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

    // Validate field_index is within bounds before array access
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

The vulnerability exists because the `field_index` extracted from the untrusted network frame (line 39: `uint8_t field_index = frame[0]`) is used directly to index the `descriptors` array without any validation. An attacker can provide a value from 0-255 in the first byte of a frame, but the `descriptors` array contains only 16 elements (indices 0-15). Any value 16 or higher causes an out-of-bounds read, reading past the end of the static array into adjacent memory.

The fix adds an explicit bounds check immediately before the array access (lines 44-46): `if (field_index >= MAX_FIELDS) { return -1; }`. This validation ensures that only valid indices 0-15 are used to access the array, preventing the out-of-bounds read. The check follows the direction-independent safe pattern from CWE-125 C guidance: validate the index against the array's known bound before dereferencing. When an invalid index is detected, the function returns -1, the same error code used for other validation failures, allowing the caller to handle the error appropriately.

## Behaviour changes

none

The fix preserves the function's contract: it still returns 0 on success, -1 on any error (including the new bounds violation), and leaves all other behavior unchanged. The caller's error handling path already exists and is exercised unchanged.
