## Verdict

Confirmed. `write_payload()` validates only `length > capacity`, then writes at `destination + offset`. It never checks `offset` against `capacity` at all, so any caller-supplied `offset` shifts the write window past the end of `destination` while the length check still passes (e.g. `offset = capacity`, `length = 1` writes one byte past the buffer, even though `length <= capacity`). `encode_frame()` passes an attacker-influenced `offset` straight through from its own caller without adjusting `capacity`, so the unchecked offset reaches the `memcpy` directly.

## Source

`offset` and `length`, received as parameters of `write_payload()` in `buffer_writer.c` (and passed through unchanged from `encode_frame()`'s `offset`/`length` parameters in `frame_encoder.c`), reach the sink with no bound placed on `offset` and an insufficient bound on `length`.

## Fix

### File: buffer_writer.c
```c
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (offset > capacity) {
        return;
    }

    if (length > capacity - offset) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

## Explanation

The original check compared `length` to the full `capacity`, ignoring that the write actually starts at `destination + offset`. Any `offset > 0` therefore let `length` be up to `capacity` bytes even though only `capacity - offset` bytes remain, producing an out-of-bounds write; an `offset` at or beyond `capacity` was not rejected at all.

The fix validates `offset` first: if `offset > capacity`, there is no room for any write and the call is rejected before doing arithmetic on `capacity - offset`. Only once `offset <= capacity` is established is `capacity - offset` computed, which is now guaranteed non-negative, so it cannot wrap around under `size_t`'s unsigned arithmetic the way `offset + length > capacity` could if `offset` and `length` were both attacker-controlled and large. `length` is then checked against that remaining space, `capacity - offset`, rather than the full buffer.

This preserves valid writes at any legitimate nonzero offset (as long as the payload still fits in the remaining space), rejects any write that would run past the end of `destination`, and keeps `capacity` supplied explicitly by the caller (`encode_frame()` in `frame_encoder.c` is unchanged) rather than having `write_payload()` infer or hardcode a buffer size.
