## Verdict

exploitable (confidence: high)

- cwe_id: CWE-787 (Out-of-bounds Write)
- location: StdArrayOperatorBracketWrite.cpp, line 29 (`calibrationTable[update.channelIndex] = update.value;`)

## Source

`applyCalibrationUpdate(const uint8_t* messageBuffer, size_t messageLength)` receives a raw byte buffer from the sensor network. The only validation performed is a length check (`messageLength < sizeof(CalibrationUpdateMessage)`), which guarantees the buffer is *large enough* but says nothing about the *values* inside it. The buffer is copied byte-for-byte into `CalibrationUpdateMessage update` via `std::memcpy`, so `update.channelIndex` is a fully attacker-controlled `uint8_t` (range 0-255) with no relationship to the destination array's size.

## Fix

### File: StdArrayOperatorBracketWrite.cpp

```cpp
#include <array>
#include <cstdint>
#include <cstring>

// Fixed-size calibration table for an 8-channel sensor bank. Each channel's
// offset is stored at a fixed slot so the control loop can read it back with
// a plain index lookup.
static std::array<double, 8> calibrationTable{};

#pragma pack(push, 1)
struct CalibrationUpdateMessage {
    uint8_t channelIndex;
    double value;
};
#pragma pack(pop)

// Applies a calibration update received from the sensor network. The message
// layout is fixed size, so the parser only needs to check the buffer is long
// enough to hold one record before reading the fields out of it.
void applyCalibrationUpdate(const uint8_t* messageBuffer, size_t messageLength) {
    if (messageBuffer == nullptr || messageLength < sizeof(CalibrationUpdateMessage)) {
        return;
    }

    CalibrationUpdateMessage update{};
    std::memcpy(&update, messageBuffer, sizeof(update));

    if (update.channelIndex >= calibrationTable.size()) {
        return;
    }

    calibrationTable[update.channelIndex] = update.value;
}
```

## Explanation

`calibrationTable` is a `std::array<double, 8>`, and `operator[]` on `std::array` performs no bounds checking - an out-of-range index is undefined behaviour that writes an 8-byte `double` past (or, for large indices, well past) the end of the 64-byte backing array, corrupting whatever static storage follows it. `update.channelIndex` is a `uint8_t` taken verbatim from the network message and can be any value 0-255, while only 0-7 are valid slots. The fix adds an explicit bounds check - `update.channelIndex >= calibrationTable.size()` - before the write, using the container's own `.size()` as the authority on capacity rather than any assumption about the sender's message format. An out-of-range index is rejected by returning early, exactly as the function already does for a null or undersized buffer, so the reject path matches the function's existing contract instead of introducing a new one (e.g. an exception from `.at()`, which this void-returning, caller-unaware function has no path to propagate). `operator[]` remains safe to use afterward because the index is now structurally guaranteed to be in range.

## Behaviour changes

- For `channelIndex` values 8-255 (previously undefined behaviour / memory corruption), the function now silently discards the update and returns without writing, identical in shape to how it already discards a message that is null or too short. No other input, return value, or side effect changes: valid updates (`channelIndex` 0-7) are written exactly as before.
- Verification: no C++ compiler (`g++`/`cl`) was reachable in this environment, so the fix was checked by hand instead of compiled. `std::array::size()` is a standard, `noexcept`, `constexpr` member (`<array>`, already included) returning `size_type` (an unsigned integral type); comparing it against `uint8_t` via `>=` is a standard integer promotion with no new warnings. No new symbols, includes, or signature changes were introduced beyond this one comparison and early return, and the edit mirrors the existing early-return validation already present in the function two lines above it.
