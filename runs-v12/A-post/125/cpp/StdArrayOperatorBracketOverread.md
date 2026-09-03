## Verdict

**CONFIRMED**: Out-of-bounds read on line 27. The `sensorIndex` field is read directly from an untrusted network message without bounds checking before indexing into an 8-element array.

## Source

The vulnerability is in the `applyCalibrationOffset` function. Line 27 accesses `calibrationTable[request.sensorIndex]` where `request.sensorIndex` is a `uint32_t` derived from untrusted network data (line 24, via `std::memcpy`). The `calibrationTable` array has only 8 valid indices (0–7), but `sensorIndex` is never validated.

An attacker controlling the network message can supply any `uint32_t` value, causing the array subscript operator to read beyond the array's bounds, leaking memory or causing undefined behavior.

## Fix

Add bounds validation before indexing:

```cpp
double applyCalibrationOffset(const uint8_t* message, size_t messageLength, double rawReading) {
    CalibrationRequest request{};
    if (messageLength < sizeof(request)) {
        return rawReading;
    }
    std::memcpy(&request, message, sizeof(request));

    // Validate sensorIndex is within array bounds
    if (request.sensorIndex >= calibrationTable.size()) {
        return rawReading;
    }

    double offset = calibrationTable[request.sensorIndex];
    return rawReading + offset;
}
```

## Explanation

The fix adds an explicit bounds check comparing `request.sensorIndex` against `calibrationTable.size()` before indexing. Since `calibrationTable` is a `std::array<double, 8>`, its size is 8, so only indices 0–7 are valid. Any index >= 8 is rejected and the function returns the raw reading unchanged.

This rejects malformed or malicious messages while preserving the function's semantics for valid inputs. The check is placed immediately after deserialization and before the sink (the array access), following the principle of validating untrusted input at the boundary where it enters the application.
