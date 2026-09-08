## Verdict

Exploitable. Confidence: high.

## Source

`headerLen` and `payloadLen`, the `uint32_t` parameters of `ReassembleFragment` (line 8-9). Per the function's own header comment, both are parsed directly from the wire header of an attacker-controlled fragment - the remote peer chooses both values.

## Sink

Line 15 computes `uint32_t totalSize = headerLen + payloadLen;`, a 32-bit addition that wraps when the two attacker-controlled lengths sum past `UINT32_MAX` (e.g. `headerLen = 0xFFFFFFF0`, `payloadLen = 0x20` wraps `totalSize` to `0x10`). Line 18, `new uint8_t[totalSize]`, then allocates a buffer sized from the wrapped value. Lines 20-21 copy `headerLen` bytes and `payloadLen` bytes into that undersized allocation via `std::memcpy`, writing far past the end of the heap buffer - CWE-787 at the `new[]`/`memcpy` pair, with the size computation on line 15 as the root cause.

Sink contract before the fix: returns a heap pointer the caller takes ownership of; has no failure path (`new[]` throws `std::bad_alloc` only on genuine allocation failure, uncaught by this function); no arguments are left implicit; nothing is discarded.

## Fix

### File: NewArrayComputedSizeOverflow.cpp

```cpp
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

// Reassembles a fragmented message from a custom binary transport protocol.
// Each fragment carries its own header and payload; headerLen and payloadLen
// are parsed directly from the fragment's wire header fields, which the
// remote peer controls.
//
// Returns nullptr if the combined length cannot be represented as a size_t
// on this platform, so the caller must check the result before use.
uint8_t* ReassembleFragment(const uint8_t* headerData, uint32_t headerLen,
                             const uint8_t* payloadData, uint32_t payloadLen)
{
    // Widen to 64 bits before adding so the two attacker-controlled 32-bit
    // lengths cannot wrap the way they could as uint32_t (e.g.
    // headerLen = 0xFFFFFFF0, payloadLen = 0x20 previously wrapped the sum
    // down to 0x10, far smaller than either input).
    uint64_t totalSize = static_cast<uint64_t>(headerLen) + static_cast<uint64_t>(payloadLen);

    // Reject a combined length that does not fit in size_t rather than
    // truncating it on the cast below, which would reintroduce the same
    // wraparound the widened addition above was meant to prevent.
    if (totalSize > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        return nullptr;
    }

    uint8_t* buffer = new uint8_t[static_cast<size_t>(totalSize)];

    std::memcpy(buffer, headerData, headerLen);
    std::memcpy(buffer + headerLen, payloadData, payloadLen);

    return buffer;
}
```

## Explanation

The overflow happened because `headerLen + payloadLen` was computed as `uint32_t`, so a sum exceeding `UINT32_MAX` wrapped to a small value before it was ever validated, and the two `memcpy` calls afterward always write the true, un-wrapped `headerLen` and `payloadLen` byte counts. Widening the addition to `uint64_t` makes the sum of any two 32-bit values (max `0x1FFFFFFFE`) representable without wrapping, so `totalSize` always equals the true combined length the two `memcpy` calls will write. The added `size_t` range check exists only to stop that correct 64-bit value from being truncated back into a narrower wraparound when it is cast down to `size_t` for `new[]` on a platform where `size_t` is narrower than 64 bits; on a typical 64-bit build the check never trips, since `size_t` there covers the full `uint64_t` range this sum can reach. On the same inputs that previously wrapped, the allocation now correctly sized to hold both fragments, so the two `memcpy` calls land entirely inside the buffer's bounds.

## Behaviour changes

- Return contract widened: the function can now return `nullptr` when the combined length does not fit in `size_t` (only reachable if `size_t` is narrower than 64 bits on the target platform - never on a standard 64-bit build, since the maximum possible sum of two `uint32_t` values always fits in a 64-bit `size_t`). Callers of this function must check for `nullptr` before dereferencing the result; this is a new failure path where previously the function only ever returned a valid pointer or let an uncaught `std::bad_alloc` propagate from `new[]`.
- On the previously wrap-triggering input (e.g. `headerLen = 0xFFFFFFF0`, `payloadLen = 0x20`), the function now attempts a genuine ~4 GiB allocation instead of silently under-allocating 16 bytes. If that allocation cannot be satisfied, `new[]` throws `std::bad_alloc`, exactly as it already could before this fix on any sufficiently large, non-overflowing request - this is not a new failure mode, just one now reachable from this previously-wrapped input.
- Added `#include <cstddef>` (for `size_t`) and `#include <limits>` (for `std::numeric_limits`); both are standard library headers with no external dependency.
- No change to behavior for any input whose combined length does not overflow `uint32_t`: `totalSize` in the fixed code equals `headerLen + payloadLen` exactly as the original arithmetic intended before it could wrap.

## Verification

No C++ compiler (`g++`, `clang++`, `cl.exe`) was reachable in this environment, so the fix was checked by hand instead of compiled: every symbol the fix adds - `std::numeric_limits` (`<limits>`), `size_t` (`<cstddef>`), `static_cast`, `uint64_t` (`<cstdint>`, already included) - is C++ standard library, correctly spelled, and used with the standard signature (`std::numeric_limits<size_t>::max()` takes no arguments and returns `size_t`). The two `memcpy` calls and the `new[]` call are otherwise untouched, and no caller of `ReassembleFragment` exists in this single-file case to update for the new `nullptr` return.

## Assumptions

- No caller of `ReassembleFragment` is present in the provided file, so the new `nullptr`-on-overflow return path cannot be cross-checked against a call site; the record above states it explicitly as a behaviour change for the calling process to account for.
- The fix returns `nullptr` on an unrepresentable size rather than throwing, matching the "report a refused write to the caller" principle from the C++ guidance while keeping the function's existing raw-pointer return type rather than changing its signature to something that can carry a richer error (which would be a larger, unrequested interface change).
