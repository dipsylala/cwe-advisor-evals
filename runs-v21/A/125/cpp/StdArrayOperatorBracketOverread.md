## Verdict

The out-of-bounds read at line 27 is real. The `request.sensorIndex` field originates from untrusted network data and is used directly as an array subscript without validation, allowing reads beyond the array's bounds.

## Source

The vulnerability exists because:
1. `request.sensorIndex` is a `uint32_t` field populated from untrusted network data via `std::memcpy()` at line 24
2. No bounds check validates that `request.sensorIndex` is within the range `[0, 7]`
3. Line 27 uses this unchecked value to subscript `calibrationTable`, a `std::array<double, 8>`
4. Any index >= 8 causes an out-of-bounds read (undefined behavior)

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

    // Bounds-check the sensorIndex before array access
    if (request.sensorIndex >= calibrationTable.size()) {
        return rawReading;
    }

    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

## Explanation

The fix adds a bounds check at line 28-30 before the array subscript. If `request.sensorIndex` is out of bounds (>= 8), the function returns the uncalibrated reading, matching the defensive pattern already established for invalid message length. This ensures the array subscript at line 33 always accesses a valid index in the range [0, 7], eliminating the out-of-bounds read.

