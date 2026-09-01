## Verdict

Exploitable. The function validates an index against a `claimedCapacity` parameter rather than the actual `std::span` size, allowing writes beyond the allocated buffer.

## Source

`advertisedLength` parameter in `telemetry_encoder.cpp::encodeTelemetry()` (untrusted external input claiming a packet capacity), passed through `claimedCapacity` parameter in `segment_writer.cpp::writeSegmentByte()`.

## Fix

**Vulnerable code:**

```cpp
void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= claimedCapacity) {  // Problem: checks against claim, not actual span size
        return;
    }

    segment[index] = value;  // Out-of-bounds write if claimedCapacity > segment.size()
}
```

**Fixed code:**

```cpp
void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= segment.size()) {  // Check against actual span capacity
        return;
    }

    segment[index] = value;
}
```

## Explanation

The vulnerability occurs because the bounds check relies on `claimedCapacity`, an external parameter that is not validated against the actual span capacity. If a caller provides an `advertisedLength` (from a packet header or similar untrusted source) that exceeds the actual buffer size, the bounds check will pass even though the write would occur out of bounds. The fix changes the validation to use `segment.size()`, the span's own tracked capacity, ensuring the index is checked against the real allocated size. This aligns with the C++ guidance principle: "the length used for the check is always the length of the data actually pointed at." The span owns this information and cannot be deceived by external claims.

## Behaviour changes

The bounds check now validates against the actual buffer size (`segment.size()`) rather than an external parameter (`claimedCapacity`). This prevents out-of-bounds writes when a caller provides a `claimedCapacity` larger than the span's true size. The checked return semantics remain unchanged: writes beyond the now-correctly-validated boundary are silently discarded. No other contract elements (return value, error handling, exceptions) are affected.

