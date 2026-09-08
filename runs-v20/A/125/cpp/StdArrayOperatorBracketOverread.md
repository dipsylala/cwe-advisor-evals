## Verdict

Confirmed. `request.sensorIndex` is a `uint32_t` read verbatim from an attacker-controlled network
message via `std::memcpy`, then used directly as the index into `calibrationTable`, a fixed
`std::array<double, 8>`. `operator[]` on `std::array` performs no bounds checking, so any
`sensorIndex` value of 8 or greater (up to `UINT32_MAX`) reads memory outside the array's backing
storage. The out-of-bounds `double` is then folded into the returned reading, so the read can
leak adjacent memory content into a value the caller trusts, or crash the process if the read
lands on an unmapped page.

## Source

`message` / `messageLength` are the network-supplied input to `applyCalibrationOffset`. They are
copied byte-for-byte into `request` via `std::memcpy(&request, message, sizeof(request))` on line
24, which populates `request.sensorIndex` directly from wire bytes controlled by any peer on the
network, per the function's own comment. No validation is applied to `sensorIndex` between that
copy and its use as an array index.

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

    // sensorIndex comes straight off the wire and must be range-checked
    // before it is used to index the fixed calibration table.
    if (request.sensorIndex >= calibrationTable.size()) {
        return rawReading;
    }

    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

## Explanation

The fix adds an explicit range check on `request.sensorIndex` against `calibrationTable.size()`
before the index is used, rejecting any wire value at or beyond the table's 8 valid channels and
falling back to the uncalibrated `rawReading` exactly as the function already does for a
too-short message. This preserves the function's existing "reject and return the raw reading"
error-handling convention rather than introducing a new one, and keeps `operator[]` for the
now-validated access rather than switching to `std::array::at()`'s exception-based checking,
which would require the caller to handle an unexpected `std::out_of_range` throw across what is
effectively a wire-parsing boundary. Because `sensorIndex` is `uint32_t` and `calibrationTable.size()`
returns `size_t`, the comparison is well-defined and does not need a separate check for negative
values. The change is a pure input-validation addition; it does not alter behavior for any
in-range `sensorIndex` (0-7).
