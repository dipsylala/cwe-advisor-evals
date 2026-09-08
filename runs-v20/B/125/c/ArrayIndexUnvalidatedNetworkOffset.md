## Verdict

Confirmed. `resolve_field_descriptor()` reads `field_index` from byte 0 of an attacker-controlled network frame and uses it to index the fixed-size `descriptors[MAX_FIELDS]` table (`MAX_FIELDS` = 16) with no bound check. `field_index` is a `uint8_t`, so it ranges 0-255; any value 16-255 reads past the end of `descriptors` at line 42 (`*out = descriptors[field_index];`).

## Source

`frame[0]`, the first byte of the inbound network frame passed into `resolve_field_descriptor(const uint8_t *frame, size_t frame_len, field_descriptor_t *out)`. The function validates `frame != NULL`, `out != NULL`, and `frame_len >= 1`, which only guarantees `frame[0]` is safe to read - it does not constrain the resulting `field_index` value in any way before it is used as an array index.

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

`field_index` is derived directly from the wire frame with no relation to the size of `descriptors`, so any value from 16 to 255 indexes past the end of the 16-entry table, reading whatever memory follows it (or, at the top of the range, running well outside the static data segment). The fix adds an explicit upper-bound check, `field_index >= MAX_FIELDS`, immediately before the array access and rejects the frame by returning -1, matching the function's existing error contract (0 on success, -1 on error, already used for the null/length checks two lines above). No lower-bound check is needed because `field_index` is `uint8_t`, an unsigned type that cannot go negative. `handle_frame()` already treats any non-zero return from `resolve_field_descriptor()` as a failure and propagates -1, so it requires no change.

## Behaviour changes

- New rejection path: frames whose first byte is >= 16 (`MAX_FIELDS`) now cause `resolve_field_descriptor()` to return -1 instead of returning descriptor data read from out-of-bounds memory. `handle_frame()` correspondingly returns -1 for such frames instead of populating `*payload_offset`/`*payload_length` with unspecified values. This affects only frames that were already malformed/out-of-spec for the current protocol table (valid field indices remain 0-3, given only 4 of the 16 table slots are populated); no change to behaviour for any currently-valid field index.
- No new APIs, libraries, or parameters introduced; no compiler available in this environment to verify the fix compiles, so it was checked by hand: the added statement uses only `field_index`, the existing `MAX_FIELDS` macro, and the `>=` operator, all already in scope, and the added `return -1;` matches the function's existing return type and error convention used by its only caller.
