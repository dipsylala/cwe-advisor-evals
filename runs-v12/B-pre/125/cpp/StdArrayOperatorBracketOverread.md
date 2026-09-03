## Verdict
exploitable

## Source
`request.sensorIndex` from untrusted network input, parsed via `memcpy()` on line 24

## Fix

**Vulnerable code:**
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

**Fixed code:**
```cpp
double applyCalibrationOffset(const uint8_t* message, size_t messageLength, double rawReading) {
    CalibrationRequest request{};
    if (messageLength < sizeof(request)) {
        return rawReading;
    }
    std::memcpy(&request, message, sizeof(request));

    // Validate that the sensor index is within the calibration table bounds
    if (request.sensorIndex >= calibrationTable.size()) {
        return rawReading;
    }

    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

## Explanation
The fix adds an explicit bounds check immediately before the array access on line 27. An attacker can craft a network message with a `sensorIndex` value (0-7 are valid) that exceeds the 8-element `calibrationTable`, causing an out-of-bounds read. The bounds check compares the untrusted `request.sensorIndex` against the array's actual `.size()` before use, matching the existing function pattern of returning the uncalibrated reading for invalid input. This closes the vulnerability by preventing any access outside the valid range [0, 8).

## Behaviour changes
none
