## Verdict
exploitable

## Source
Network message data received via the `message` parameter, parsed via `std::memcpy()` into the `request` struct. The `sensorIndex` field is extracted directly from untrusted input without validation.

## Fix

**Vulnerable code:**
```cpp
double offset = calibrationTable[request.sensorIndex];
```

**Fixed code:**
```cpp
// Validate the sensor index is within the calibration table bounds
if (request.sensorIndex >= calibrationTable.size()) {
    return rawReading;  // Invalid sensor index, return raw reading unchanged
}
double offset = calibrationTable[request.sensorIndex];
```

## Explanation
The vulnerability occurs because `calibrationTable` is a fixed-size `std::array<double, 8>` with exactly 8 valid indices (0–7), but `request.sensorIndex` is a `uint32_t` read from untrusted network input with no bounds check. An attacker can supply any value for `sensorIndex`, including values >= 8, causing `operator[]` to read memory beyond the array's allocated buffer. The fix adds an explicit bounds check using `.size()` immediately before the array access, following the C++ guidance preference for validating untrusted indices inside the function before use. If the index is out of range, the function returns the raw reading unchanged, consistent with the existing error-handling pattern for invalid input (short messages also return `rawReading`).

## Behaviour changes
The function now rejects invalid sensor indices (>= array size) by returning `rawReading` without applying the offset. This is a safe behavior change: previously invalid indices would read uninitialized or attacker-influenced memory; now they are explicitly rejected. This matches the function's existing pattern of returning `rawReading` when input cannot be processed (see line 22–23 for the short message case).
