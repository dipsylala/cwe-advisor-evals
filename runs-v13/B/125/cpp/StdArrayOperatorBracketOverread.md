## Verdict

Real. The code at line 27 reads `calibrationTable[request.sensorIndex]` where `request.sensorIndex` is copied directly from untrusted network input without validation. The `calibrationTable` has size 8, so any index >= 8 or negative (when cast to unsigned) reads past the array bounds.

## Source

```cpp
double applyCalibrationOffset(const uint8_t* message, size_t messageLength, double rawReading) {
    CalibrationRequest request{};
    if (messageLength < sizeof(request)) {
        return rawReading;
    }
    std::memcpy(&request, message, sizeof(request));

    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

## Fix

Add a bounds check immediately before the array access:

```cpp
double applyCalibrationOffset(const uint8_t* message, size_t messageLength, double rawReading) {
    CalibrationRequest request{};
    if (messageLength < sizeof(request)) {
        return rawReading;
    }
    std::memcpy(&request, message, sizeof(request));

    // Validate sensorIndex is within the calibrationTable bounds (0-7)
    if (request.sensorIndex >= calibrationTable.size()) {
        return rawReading;
    }

    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

## Explanation

The vulnerability exists because `request.sensorIndex` originates from untrusted network input. The `memcpy` on line 24 copies 20 bytes (the CalibrationRequest structure) from the network message directly into local memory, so an attacker can supply any uint32_t value for `sensorIndex`. Without validation, this index is used to read from `calibrationTable`, a fixed-size `std::array<double, 8>`. An index >= 8 causes an out-of-bounds read of whatever follows the array in memory.

The fix adds an explicit bounds check that validates `request.sensorIndex` against `calibrationTable.size()` (which is 8) immediately before the read. This follows the CWE-125 C++ guidance to validate the index before every access and to check bounds explicitly rather than rely on unchecked `operator[]`. The check is placed in the same function that performs the read, not offloaded to a caller.

The comparison `request.sensorIndex >= calibrationTable.size()` is safe because both operands are unsigned integers and there is no arithmetic that could overflow.

## Behaviour changes

- **Error case**: An inbound message with `sensorIndex >= 8` now returns the raw reading unchanged, instead of reading memory past the calibration array.
- **Normal case**: Valid sensor indices (0-7) continue to work exactly as before; the bounds check passes and the offset is applied normally.
- **No exceptions thrown**: The fix uses early return rather than exceptions, consistent with the existing error-handling pattern in this function.
