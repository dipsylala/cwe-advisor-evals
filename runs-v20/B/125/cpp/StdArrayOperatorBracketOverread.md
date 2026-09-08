## Verdict

exploitable

- cwe_id: CWE-125 (Out-of-bounds Read)
- location: SensorCalibration.cpp, line 27 (`double offset = calibrationTable[request.sensorIndex];`)
- confidence: high

## Source

`request.sensorIndex` (a `uint32_t`) is copied verbatim from the raw network message at line 24 (`std::memcpy(&request, message, sizeof(request));`), where `message` is the function's untrusted, network-supplied byte buffer. The comment on the function already documents that the value is "read straight off the wire from a device that any peer on the network can impersonate." The only check performed before line 24 is `messageLength < sizeof(request)`, which validates the size of the incoming message, not the value of `sensorIndex` inside it. Nothing on the path between the `memcpy` and line 27 constrains `sensorIndex` to the calibration table's valid range of 0-7, so the value reaches the sink unvalidated.

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

    if (request.sensorIndex >= calibrationTable.size()) {
        return rawReading;
    }
    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

## Explanation

`sensorIndex` is an unsigned 32-bit field copied directly from an attacker-controlled network message, and `std::array::operator[]` performs no bounds check, so any value 8 or greater reads past the end of the 8-element `calibrationTable` (undefined behaviour, and a likely information-disclosure or crash primitive since the index is fully attacker-controlled up to `UINT32_MAX`). The fix adds an explicit range check, `request.sensorIndex >= calibrationTable.size()`, immediately before the read and before the value is used at all. Because `sensorIndex` is unsigned, only the upper bound needs checking; comparing against `calibrationTable.size()` (rather than a hard-coded `8`) ties the check to the container's actual current size, so it stays correct if the table is ever resized. On an invalid index the function returns `rawReading` unmodified, mirroring the failure behaviour the function already uses one line above for an undersized message, rather than throwing or silently substituting a placeholder offset.

## Behaviour changes

- Added: for `sensorIndex >= 8`, the function now returns `rawReading` unchanged instead of reading adjacent memory and adding whatever value happens to sit there. This is the intended effect of the fix, not a side effect - the prior behaviour was undefined and not a real code path to preserve. It follows the same "return `rawReading` on invalid input" contract the function already establishes for the `messageLength < sizeof(request)` case, so callers do not need to handle a new failure mode (no exception, no new return type).
- No other differences: no arguments added or removed, no change to the return type, no change to behaviour for the valid range `sensorIndex` in `[0, 7]`.

## Verification

No C++ compiler (`g++`, `clang++`, `cl`) was reachable in this environment, so the fix was verified by manual read rather than compilation:
- The only new expression is `request.sensorIndex >= calibrationTable.size()`. `request.sensorIndex` is the pre-existing `uint32_t` field; `std::array<double, 8>::size()` is a standard-library member (`<array>`, already included) returning `std::size_t`, and comparing `uint32_t` to `std::size_t` is a standard, well-defined unsigned comparison (usual arithmetic conversions promote to the wider unsigned type) that introduces no signed/unsigned mismatch.
- No new includes, types, or external names were introduced.
- Control flow mirrors the existing early-return guard for `messageLength < sizeof(request)` immediately above it, so the function's structure and single-return-type contract (`double`) are unchanged.
- Assumption: returning `rawReading` unmodified for an out-of-range `sensorIndex` (rather than propagating an error, e.g. via `.at()` and an exception) was chosen to match the failure behaviour already established by the function's existing bounds check, since the function's `double` return type has no channel for a distinct error status and no caller/exception-handling context was available in the provided file to confirm an exception would be handled correctly further up the stack.
