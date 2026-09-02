## Verdict

Exploitable. `writeSegmentByte` bounds-checks `index` against `claimedCapacity`, a value supplied by the caller as a *claim* about how much data is valid, rather than against `segment.size()`, the actual extent of the `std::span` backing the write. When a caller passes a `claimedCapacity` larger than the real span, indices in the range `[segment.size(), claimedCapacity)` pass the check at line 6 and reach `segment[index] = value` at line 10, writing past the end of the underlying buffer. This is CWE-787: the length is a statement about how much was sent/claimed, not about how much room exists to store it.

## Source

`advertisedLength`, the second parameter of `encodeTelemetry` (telemetry_encoder.cpp:7) - an externally-influenced length claim associated with the telemetry packet (e.g. a declared/advertised size field, independent of the actual `packet` span's extent). It flows unmodified into `writeSegmentByte` as `claimedCapacity` (telemetry_encoder.cpp:8 -> segment_writer.cpp:5), where it alone gates the write at segment_writer.cpp:6, and the write itself, `segment[index] = value`, is the sink at segment_writer.cpp:10.

## Fix

Vulnerable code (segment_writer.cpp):

```cpp
void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= claimedCapacity) {  // bounds check uses the caller's claimed length, not the span's real size
        return;
    }

    segment[index] = value;
}
```

Fixed code (segment_writer.cpp):

```cpp
void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= claimedCapacity || index >= segment.size()) {
        return;
    }

    segment[index] = value;
}
```

## Explanation

The fix adds `index >= segment.size()` to the guard so the write is rejected whenever `index` falls outside the span's actual backing storage, regardless of what `claimedCapacity` asserts. `segment.size()` reflects the real extent of the memory `segment` points at, so this check cannot be defeated by a caller supplying an inflated or otherwise untrustworthy `claimedCapacity`. The pre-existing `claimedCapacity` check is left in place since it may encode a legitimate, tighter logical limit (e.g. restricting writes to a sub-region the protocol has actually populated); the added check only ever makes the function more restrictive, never less, and closes the out-of-bounds write.

## Behaviour changes

For every index that was already in range for both `claimedCapacity` and `segment.size()` - the intended, non-malicious case - behaviour is unchanged: the function still writes `value` at `index` and returns normally. The only change in observable behaviour is for indices where `claimedCapacity > segment.size()` and `index` falls in between: previously the function performed an out-of-bounds write (undefined behaviour); it now takes the existing early-return path and performs no write, silently declining exactly as it already does for an index rejected by the `claimedCapacity` check. No argument, return type, or discarded value was added or altered, so the function's contract (void return, silent no-op on rejection) is preserved.
