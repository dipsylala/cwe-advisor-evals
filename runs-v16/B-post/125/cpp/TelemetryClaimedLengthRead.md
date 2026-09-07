## Verdict

CONFIRMED. Out-of-bounds read at line 12. The function validates `offset` but not `length`, allowing `offset + i` to exceed `frame.size()` when `length` is larger than the remaining buffer.

## Source

The function accepts `offset` and `length` as parameters without validating that their sum does not exceed the buffer size. The bounds check at lines 6-8 validates `offset` alone and returns early if out of range, but does not constrain `length`.

Data flow:
- **Source**: `length` parameter (untrusted input)
- **Sink**: Line 12, `frame[offset + i]` using `operator[]`
- **Path**: For-loop iterates from `i = 0` to `i < length`. When `offset + i >= frame.size()`, the access reads out-of-bounds memory.

Example trigger: `offset = 5`, `frame.size() = 10`, `length = 10`. The check `offset >= frame.size()` (line 6) passes, but the loop at line 11-12 accesses `frame[10]` through `frame[14]`, all beyond the allocated buffer.

## Fix

```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }

    // Validate offset + length does not exceed frame bounds (unsigned overflow-safe check)
    if (length > frame.size() || offset > frame.size() - length) {
        return 0;
    }

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < length; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];
    }

    return checksum;
}
```

## Explanation

Added a second bounds check (lines 9-11) immediately before the loop that validates the combined `offset + length` does not exceed `frame.size()`. The check order follows CWE-125/cpp guidance to avoid unsigned arithmetic wrap: first `length > frame.size()` (protecting against oversized length), then `offset > frame.size() - length` (protecting against overshoot). Both are `std::size_t` (unsigned), so this order prevents the subtraction from wrapping to a huge value and bypassing the guard. Returns 0 on bounds violation, preserving the existing error contract.

## Behaviour changes

- **Valid inputs** (where `offset + length <= frame.size()`): No change. The function computes and returns the checksum as before.
- **Invalid inputs** (where `offset + length > frame.size()`): Previously read out-of-bounds memory; now returns 0. Callers must handle the 0 return as an error condition or decide if a partial checksum is acceptable (backward-incompatible change if callers do not differentiate a checksum of 0 from an error, but correct).
