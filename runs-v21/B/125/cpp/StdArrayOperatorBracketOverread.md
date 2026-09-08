## Verdict
exploitable

## Source
Network-supplied message data (`const uint8_t* message`) parsed via `std::memcpy` into a `CalibrationRequest` structure, where the `sensorIndex` field (type `uint32_t`) is extracted from untrusted input without validation.

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

    // Validate sensorIndex is within the bounds of calibrationTable
    if (request.sensorIndex >= calibrationTable.size()) {
        return rawReading;
    }
    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

## Explanation
The vulnerability occurs because `request.sensorIndex`, derived directly from untrusted network input, is used as an index into `calibrationTable` (an 8-element `std::array`) without bounds validation. C++'s `operator[]` on `std::array` performs no runtime bounds checking, so any index >= 8 reads arbitrary memory past the array's end, violating CWE-125. The fix adds an explicit bounds check immediately before the read: if `sensorIndex >= calibrationTable.size()`, the function returns the raw reading unchanged, matching the existing error-handling pattern. This ensures the index is always within [0, 7] before any access, and the subsequent `operator[]` read is safe. The check uses the array's own `.size()` method rather than a hardcoded constant, making the code maintainable if the table size changes.

## Behaviour changes
none
