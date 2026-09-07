## Verdict

Exploitable. The index passed to `std::array::operator[]` is read directly from untrusted network data without bounds validation.

## Source

The `request.sensorIndex` field (a `uint32_t`) is populated at line 24 via `std::memcpy()` from an untrusted network message. An attacker can send a message with a `sensorIndex` value of 8 or larger, causing the array access at line 27 to read past the end of the 8-element `calibrationTable`.

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

    // Validate sensorIndex is within bounds before accessing the calibration table
    if (request.sensorIndex >= calibrationTable.size()) {
        return rawReading;
    }

    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

## Explanation

The fix adds a bounds check immediately before the array access. The untrusted `request.sensorIndex` is compared against `calibrationTable.size()` (which is 8). If the index is out of range, the function returns early with the unmodified `rawReading`, matching the existing error-handling pattern for malformed input. This eliminates the out-of-bounds read because the array access at line 27 (now line 32) can only execute when `request.sensorIndex` is guaranteed to be in the range [0, 7].

## Behaviour changes

When a network message contains a `sensorIndex` value of 8 or greater, the function now returns the unmodified `rawReading` instead of attempting to read out-of-bounds memory. This is a safety improvement with minimal impact: invalid sensor indices are treated the same as other malformed input, returning an uncalibrated reading rather than crashing or leaking memory.
