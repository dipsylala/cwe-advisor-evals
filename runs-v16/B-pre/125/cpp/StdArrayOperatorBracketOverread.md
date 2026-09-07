## Verdict

Exploitable. The code reads from `calibrationTable` using an untrusted index (`request.sensorIndex`) received directly from a network message, with no bounds validation. The index is a `uint32_t` that can represent any value from 0 to 4,294,967,295, but `calibrationTable` is a `std::array<double, 8>` with only valid indices 0-7. An attacker controlling the network message can supply an arbitrary index value, causing the code to read memory outside the array's bounds.

## Source

`request.sensorIndex` is a `uint32_t` deserialized from untrusted network input at line 24:
```
std::memcpy(&request, message, sizeof(request));
```

The structure member `CalibrationRequest::sensorIndex` receives this untrusted value without validation.

## Fix

**Vulnerable code:**
```cpp
double offset = calibrationTable[request.sensorIndex];  // Line 27: no bounds check
```

**Fixed code:**
```cpp
// Validate sensorIndex is within bounds of the calibration table
if (request.sensorIndex >= calibrationTable.size()) {
    return rawReading;
}
double offset = calibrationTable[request.sensorIndex];
```

Insert the bounds check immediately before line 27. The check compares the untrusted index against the array's actual size before any subscript operation.

## Explanation

The fix adds an explicit, overflow-safe bounds check before reading from the array. When `request.sensorIndex` exceeds the valid range [0, 7], the function returns the raw reading unchanged rather than attempting the out-of-bounds access. This preserves the function's existing error-handling pattern (returning `rawReading` when the calibration cannot be applied) and satisfies the requirement to validate array indices against the container's actual size before every read. The check `request.sensorIndex >= calibrationTable.size()` is safe against integer overflow because both operands are non-negative and the comparison is in one direction only; the implicit conversion of `size_t` does not create a wrapping condition here.

## Behaviour changes

None. The fix changes only the sink operation (adds a guard before subscripting). The return value, error path, and calling convention remain identical: when the index is valid, the function proceeds to apply the offset; when invalid, it returns `rawReading` exactly as it does when the message is too short. No arguments are added or removed, no exceptions are introduced, and no discarded output is surfaced.
