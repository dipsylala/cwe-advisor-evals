## Verdict

Confirmed. `resolve_field_descriptor()` uses an attacker-controlled byte from the wire, `frame[0]`, as a direct index into the fixed-size `descriptors` array without checking it against the array's bound.

## Source

`frame[0]` in `resolve_field_descriptor()` (`ArrayIndexUnvalidatedNetworkOffset.c`, line 39) — the first byte of an inbound network frame, fully attacker-controlled and read into `field_index` with no upper-bound check. `frame_len < 1` is checked, but that only guarantees the byte exists, not that its value is a legal index.

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

`field_index` is a `uint8_t`, so it ranges 0-255, while `descriptors` only has `MAX_FIELDS` (16) entries. Any inbound frame whose first byte is 16 or greater makes `descriptors[field_index]` read past the end of the array, returning whatever memory happens to follow it (an out-of-bounds read, and if that struct is later trusted for a downstream copy length, a potential path to an out-of-bounds write as well).

The fix adds an explicit bounds check, `field_index >= MAX_FIELDS`, immediately after the value is read off the wire and before it is used as an index, rejecting the frame with the same `-1` error path already used for the other input-validation failures in this function. This keeps the valid range in sync with the array's actual size (`MAX_FIELDS`) rather than a hardcoded magic number, so the check keeps tracking the table if it is ever resized. No other behavior changes: legitimate indices (0-3, or any populated slot up to 15) resolve exactly as before.
