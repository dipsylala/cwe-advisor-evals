## Verdict

exploitable (confidence: high)

- cwe_id: CWE-125
- location: TelemetryClaimedLengthRead.cpp, line 12 (`checksum = (checksum << 5) ^ frame[offset + i];`)

## Source

The `length` parameter to `checksumTelemetryWindow` - a claimed/expected window length handed in by the caller alongside the actual `frame` buffer, rather than derived from `frame.size()` itself. The function validates `offset` against `frame.size()` (line 6) but never validates `length` against the buffer at all, so any caller that forwards a length taken from telemetry framing data (a field that can legitimately disagree with the number of bytes actually received) drives the read past the end of `frame`.

## Fix

Vulnerable code:

```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < length; ++i) {
        // BUG: length is never checked against frame.size() - offset,
        // so frame[offset + i] reads past the end of the buffer whenever
        // the caller-supplied length exceeds what remains in frame.
        checksum = (checksum << 5) ^ frame[offset + i];
    }

    return checksum;
}
```

Fixed code:

```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }
    if (length > frame.size() - offset) {
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

The added check `length > frame.size() - offset` validates the claimed window length against what is actually left in `frame` after `offset`, before the loop performs any read. Because `offset < frame.size()` is already guaranteed by the preceding check, `frame.size() - offset` cannot underflow, so the subtraction is a safe way to compare `offset + length` against `frame.size()` without risking the overflow that computing `offset + length` directly could introduce for a very large `length`. With this in place, `i` never lets `offset + i` reach or exceed `frame.size()`, so `frame[offset + i]` (line 12, still `operator[]`) is bounds-safe by construction rather than by luck, and `.at()` is not needed for defence in depth here since the index is now structurally guaranteed rather than merely assumed.

## Behaviour changes

Callers that previously passed a `length` extending past the end of `frame` got undefined behaviour (an out-of-bounds read, with whatever garbage checksum or crash resulted); they now get a defined return value of `0`, matching the existing convention this function already uses for an out-of-range `offset`. No other input's behaviour changes: for every `(offset, length)` pair that was already in-bounds, the fixed function computes the identical checksum via the identical loop. The function's signature, return type, and non-throwing behaviour are unchanged.
