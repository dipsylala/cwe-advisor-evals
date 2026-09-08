## Verdict

exploitable

- cwe_id: CWE-787 (Out-of-bounds Write)
- location: `buffer_writer.c:10`, `write_payload()`, the `memcpy(destination + offset, payload, length)` call
- confidence: high

## Source

`encode_frame()` in `frame_encoder.c` receives `offset` and `length` as parameters (frame header fields, per the case naming) and forwards them unvalidated, along with the fixed 256-byte `frame->bytes` buffer and its `frame->capacity`, into `write_payload()`. Neither `offset` nor `length` is checked against `frame->capacity` before the call.

## Fix

### File: buffer_writer.c

```c
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (offset > capacity || length > capacity - offset) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

## Explanation

`write_payload()` is the sink and the only place the fix needs to change: it already receives the destination's true capacity, but its guard, `if (length > capacity) return;`, checks `length` alone and never accounts for `offset`. Any caller passing a nonzero `offset` - as `encode_frame()` does, with an offset that traces back to a frame header field - can pass the `length > capacity` check while `offset + length` still exceeds `capacity`, so `memcpy` writes past the end of `destination` (here, `frame->bytes[256]`). The fix validates in the order the CWE-787 C guidance prescribes: first `offset > capacity`, rejecting an offset that is already out of range, then `length > capacity - offset`, which is the safe rearrangement of `offset + length > capacity` that cannot overflow (`capacity - offset` is computed only after `offset` is known not to exceed `capacity`, so the subtraction cannot underflow). Both `offset` and `length` are `size_t` (unsigned), so an out-of-range `offset` on its own would otherwise make `capacity - offset` wrap to a huge value and defeat the check if the two conditions were combined or reordered. On failure the function still just returns, doing nothing, exactly as it did before - the failure behaviour and the void return contract are both preserved.

## Behaviour changes

- Calls where `offset == 0`: behaviour is unchanged - `length > capacity` and `length > capacity - 0` are the same test.
- Calls where `offset > 0` and `offset + length <= capacity`: still succeed and copy, as before (these were never rejected and remain accepted).
- Calls where `offset > 0` and `offset + length > capacity` (including `offset > capacity` outright): previously wrote out of bounds; now the function returns without writing, matching its existing "reject and do nothing" failure behaviour rather than introducing a new one. This is the vulnerability closing, not an unrelated behaviour change.
- No arguments, return type, or discarded output were altered; no new APIs, functions, or dependencies were introduced - the fix is confined to the existing `if` condition in `write_payload()`.

## Verification

No C compiler (`gcc`, `clang`, `cc`) was reachable in this environment, so the fix was checked by hand rather than compiled: `offset`, `capacity`, and `length` are the function's existing `size_t` parameters (no new symbols introduced); the condition is well-formed C matching the CWE-787/C guidance's prescribed order (`offset <= capacity` first, then `length <= capacity - offset`) which avoids unsigned underflow; braces, includes, and the `memcpy` call are unchanged from the original. `frame_encoder.c` was reviewed and requires no change - `encode_frame()` already passes `frame->bytes` and `frame->capacity` straight through, and the corrected check in `write_payload()` now validates both `offset` and `length` against that real capacity regardless of caller.
