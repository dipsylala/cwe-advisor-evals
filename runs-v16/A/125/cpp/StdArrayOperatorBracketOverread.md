## Verdict
**CONFIRMED**. The code at line 27 performs an unchecked array index operation on untrusted data. The `request.sensorIndex` field is read directly from network-supplied message bytes via `std::memcpy` without bounds validation, then used to index into a fixed-size `std::array<double, 8>`. An attacker providing a sensorIndex value >= 8 triggers an out-of-bounds read.

## Source
```cpp
// Line 19-30 of SensorCalibration.cpp
double applyCalibrationOffset(const uint8_t* message, size_t messageLength, double rawReading) {
    CalibrationRequest request{};
    if (messageLength < sizeof(request)) {
        return rawReading;
    }
    std::memcpy(&request, message, sizeof(request));

    // VULNERABLE: No bounds check on request.sensorIndex before array access
    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

The vulnerability: `request.sensorIndex` is a `uint32_t` (4 bytes) but `calibrationTable` is only 8 elements. An attacker can send any uint32_t value, causing the index operator to read beyond the array bounds.

## Fix
Add a bounds check on `request.sensorIndex` before using it to index the array. Return the raw reading unmodified if the sensor index is invalid:

```cpp
double applyCalibrationOffset(const uint8_t* message, size_t messageLength, double rawReading) {
    CalibrationRequest request{};
    if (messageLength < sizeof(request)) {
        return rawReading;
    }
    std::memcpy(&request, message, sizeof(request));

    // Validate the sensor index is within bounds
    if (request.sensorIndex >= calibrationTable.size()) {
        return rawReading;
    }

    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

The check `request.sensorIndex >= calibrationTable.size()` ensures the index is in the valid range [0, 7] before array access.

## Explanation
CWE-125 (Out-of-bounds Read) occurs when untrusted input controls an array index without validation. Here, `request.sensorIndex` originates from network-supplied bytes, making it attacker-controlled. The `std::array<double, 8>` has valid indices 0-7. Using an unchecked uint32_t as an index allows reading adjacent memory beyond the array's bounds.

The fix validates the index against the array size before access. `std::array::size()` returns the compile-time size (8 in this case). Since the index is an unsigned type, we only need to check the upper bound; underflow is not a concern. The early return preserves the intended behavior for out-of-range values by returning the raw reading without a calibration offset, which is safe and reasonable for an invalid sensor index.
