## Verdict

exploitable (confidence: high)

CWE-787 (Out-of-bounds Write), C, `buffer_writer.c:10`.

## Source

`encode_frame()` in `frame_encoder.c` receives `offset` and `length` as parameters (their ultimate origin is outside the two files in this call chain, so they are treated as untrusted) and passes them unchanged, along with `frame->bytes` and `frame->capacity`, into `write_payload()`.

## Fix

Vulnerable code (`buffer_writer.c`):

```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (length > capacity) {  // does not account for offset
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

Fixed code:

```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (offset > capacity || length > capacity - offset) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

## Explanation

The sink is `memcpy(destination + offset, payload, length)` at line 10. The existing guard, `length > capacity`, only bounds `length` against the destination's total capacity and never accounts for `offset`; any caller-supplied `offset` shifts the write start arbitrarily far past `destination`, so `offset + length` can exceed `capacity` (or `offset` alone can already be past the end) even though the guard passes, corrupting memory adjacent to `frame->bytes`. The fix validates `offset <= capacity` first, then `length <= capacity - offset`, in that order so the subtraction cannot underflow (both are `size_t`). This confines every write to the `[offset, offset + length)` range within `[0, capacity)`, matching the destination's real capacity rather than trusting the caller's claim.

## Behaviour changes

None for any input where the original check already permitted the write (in that region `offset > 0` combined with `length <= capacity` did not previously imply `offset + length <= capacity`, so those in-bounds-per-old-check-but-actually-out-of-bounds calls now correctly return without writing rather than corrupting memory - that is the vulnerability being closed, not a behavioural regression). The function's return type, its silent-failure convention (return with no write, no error signaled to the caller), and `memcpy`'s discarded return value are all unchanged. Assumption: `frame->capacity` is trusted elsewhere in the codebase to reflect the true size of `frame->bytes` (256 bytes); that invariant is outside this two-file call chain and was not re-verified here.
