## Verdict

**CONFIRMED**: CWE-125 Out-of-bounds Read at line 27. The code uses `request.sensorIndex` (a uint32_t from untrusted network data) directly as an array index without bounds checking on a fixed array of 8 elements. An attacker can supply a sensorIndex value >= 8 to read arbitrary memory.

## Source

Line 27 in SensorCalibration.cpp attempts to access `calibrationTable[request.sensorIndex]` where `calibrationTable` has size 8 (valid indices 0-7), but `request.sensorIndex` is an untrusted uint32_t value from network input with no validation.

## Fix

### File: SensorCalibration.cpp

```cpp
#include <array>
#include <cstdint>
#include <cstring>

// Fixed set of factory-set calibration offsets, one per physical sensor
// channel on the device (channels 0-7).
static const std::array<double, 8> calibrationTable = {
    0.102, -0.045, 0.033, 0.198, -0.077, 0.010, 0.256, -0.014
};

struct CalibrationRequest {
    uint32_t sensorIndex;
    uint8_t payload[16];
};

// Parses an inbound network message and applies the calibration offset for
// the sensor channel it names. sensorIndex is read straight off the wire
// from a device that any peer on the network can impersonate.
double applyCalibrationOffset(const uint8_t* message, size_t messageLength, double rawReading) {
    CalibrationRequest request{};
    if (messageLength < sizeof(request)) {
        return rawReading;
    }
    std::memcpy(&request, message, sizeof(request));

    // Validate sensorIndex is within bounds before array access
    if (request.sensorIndex >= calibrationTable.size()) {
        return rawReading;
    }

    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

## Explanation

The vulnerability occurs because `request.sensorIndex` is read directly from untrusted network data without validation. The original code treats it as a valid array index despite being a uint32_t, which can hold values far exceeding the array size of 8.

The fix adds an explicit bounds check before array access:
- Compare `request.sensorIndex` against `calibrationTable.size()` (the correct upper bound)
- Return the unmodified `rawReading` if the index is out of bounds
- Only access the array if the index passes validation

This ensures the array access is always within bounds, preventing out-of-bounds memory reads that could leak sensitive data or cause undefined behavior.
