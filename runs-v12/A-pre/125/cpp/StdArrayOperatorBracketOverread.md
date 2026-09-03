## Verdict
Confirmed CWE-125 (Out-of-bounds Read). The array access is not guarded against out-of-bounds indices.

## Source
Line 24 deserializes untrusted network data into a `CalibrationRequest` struct via `std::memcpy`. The `sensorIndex` field (a `uint32_t`) is extracted from this struct without validation and used directly as an array index on line 27, where `calibrationTable` is a fixed-size `std::array<double, 8>` with valid indices 0-7 only.

## Fix
Add bounds checking before the array access to ensure `request.sensorIndex` is within the valid range [0, 7]:

```cpp
double offset = 0.0;
if (request.sensorIndex < calibrationTable.size()) {
    offset = calibrationTable[request.sensorIndex];
}
return rawReading + offset;
```

Alternatively, use `at()` instead of `operator[]`, which throws an exception on out-of-bounds access:

```cpp
try {
    double offset = calibrationTable.at(request.sensorIndex);
    return rawReading + offset;
} catch (const std::out_of_range&) {
    return rawReading;
}
```

## Explanation
The `std::array::operator[]` performs no bounds checking; it is the programmer's responsibility to ensure the index is valid. Since `sensorIndex` comes directly from untrusted network input, an attacker can craft a message with an index >= 8, causing the read to access memory beyond the array's bounds. The fix validates that the index is within [0, calibrationTable.size()) before accessing the array. This prevents the out-of-bounds read and returns a safe default (zero offset) for invalid sensor indices, maintaining the function's contract while rejecting malicious input.
