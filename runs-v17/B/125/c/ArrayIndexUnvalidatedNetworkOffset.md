## Verdict

The finding is confirmed as a real out-of-bounds read vulnerability. The `field_index` is read directly from untrusted network data without bounds validation before array access.

## Source

Line 39: `uint8_t field_index = frame[0];`

The field index originates from the first byte of an inbound network frame, passed to the function via the `frame` parameter. The caller `handle_frame()` receives this frame from untrusted input. The value is read directly into a `uint8_t` without any range validation.

The vulnerability manifests at line 42 where the unvalidated index is used to access the `descriptors` array, which holds only `MAX_FIELDS` (16) elements. A `uint8_t` can hold values 0–255, so any value 16 or higher causes an out-of-bounds read.

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

    // Validate that the field index is within the bounds of the descriptors array
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

The fix adds an explicit bounds check immediately before the array access. At line 42 (now line 45), the code validates that `field_index < MAX_FIELDS` before dereferencing `descriptors[field_index]`. If the index is out of bounds, the function returns -1 to signal an error to the caller, preventing any out-of-bounds read.

This check enforces that only valid indices (0–15) are used to access the 16-element array. The bounds check is performed while the value is still a `uint8_t`, so there is no risk of signed-to-unsigned conversion bypass. The check is placed immediately before the sink (the array access), in the same function that performs the read, as prescribed by the CWE-125 guidance.

## Behaviour changes

- **Error handling**: The function now returns -1 when `field_index >= MAX_FIELDS`, instead of reading arbitrary memory
- **Return value**: Callers of `resolve_field_descriptor()` may now receive -1 for out-of-range indices, which they already handle (see `handle_frame()` at line 56)
- **Memory safety**: Out-of-bounds reads are eliminated; only valid descriptors at indices 0–15 are accessed
