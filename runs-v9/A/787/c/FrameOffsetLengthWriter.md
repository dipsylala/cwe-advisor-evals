## Verdict

Confirmed. `write_payload()` in `buffer_writer.c` validates only `length` against `capacity` and ignores `offset`, so `memcpy(destination + offset, payload, length)` can write past the end of the destination buffer whenever `offset` is nonzero.

## Source

`encode_frame()` in `frame_encoder.c` accepts an attacker/caller-controlled `offset` and `length` and forwards them, along with the fixed-size 256-byte `frame->bytes` buffer (via `frame->capacity`), to `write_payload()`:

```c
void encode_frame(struct Frame *frame, size_t offset, const uint8_t *payload, size_t length) {
    write_payload(frame->bytes, frame->capacity, offset, payload, length);
}
```

Neither function bounds-checks `offset` before it is added to the destination pointer.

## Fix

Replace the bounds check in `write_payload()` (`buffer_writer.c`) so it validates the full write range `[offset, offset + length)` against `capacity`, guarding against integer overflow in the addition:

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

`capacity - offset` is computed only after confirming `offset <= capacity`, so the subtraction cannot wrap, and the subsequent comparison correctly rejects any `length` that would carry the write past `destination + capacity`.

## Explanation

The original check `if (length > capacity) return;` only bounds `length` in isolation; it never considers where in the buffer the write begins. Because the actual write targets `destination + offset`, the valid write range shrinks as `offset` grows, but the check never accounts for that. Any call with `offset > 0` and `length` close to `capacity` (or simply `offset >= capacity`) passes the check yet writes outside `frame->bytes[256]`, corrupting adjacent memory in `struct Frame` or beyond it — a classic out-of-bounds write (CWE-787).

The fix restores the invariant that must hold before any bounded write: the destination offset must itself be within the buffer (`offset <= capacity`), and the remaining space from that offset to the end of the buffer (`capacity - offset`) must be large enough to hold `length` bytes. Performing the subtraction only after the first check avoids unsigned wraparound, which would otherwise let a crafted `offset` bypass the second comparison entirely. This keeps `write_payload()` a general-purpose, reusable bounds check regardless of how `offset` and `length` are produced upstream in `encode_frame()`.
