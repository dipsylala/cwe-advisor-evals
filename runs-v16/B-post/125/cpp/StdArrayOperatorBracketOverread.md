## Verdict

Real. The network-sourced `request.sensorIndex` is used without bounds validation to index a fixed-size `std::array` of 8 elements, creating an out-of-bounds read.

## Source

`request.sensorIndex` is a `uint32_t` field copied directly from network input via `std::memcpy()` on line 24. The input is untrusted (as noted in the comment on line 18: "sensorIndex is read straight off the wire from a device that any peer on the network can impersonate"). This value is then used on line 27 as an unchecked index into `calibrationTable`, a `std::array<double, 8>`.

## Fix

```cpp
double applyCalibrationOffset(const uint8_t* message, size_t messageLength, double rawReading) {
    CalibrationRequest request{};
    if (messageLength < sizeof(request)) {
        return rawReading;
    }
    std::memcpy(&request, message, sizeof(request));

    // Validate index before accessing array
    if (request.sensorIndex >= calibrationTable.size()) {
        return rawReading;
    }
    double offset = calibrationTable[request.sensorIndex];

    return rawReading + offset;
}
```

## Explanation

The fix adds an explicit bounds check comparing `request.sensorIndex` against `calibrationTable.size()` before indexing. Per the CWE-125 C++ guidance, `operator[]` on `std::array` performs no bounds check and reads undefined memory if the index exceeds the container size. The untrusted network input requires validation before use. If the index is out of bounds, the function returns the uncalibrated reading, maintaining the existing error-handling pattern of the function (returning `rawReading` unchanged when calibration cannot be applied safely).

## Behaviour changes

- When `request.sensorIndex >= 8`, the function now returns `rawReading` without applying a calibration offset, instead of reading undefined memory
- Requests with invalid sensor indices (e.g., 100, 255) are treated as invalid inputs and handled gracefully
- Performance impact is negligible: one unsigned comparison added before array access
