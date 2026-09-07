## Verdict

Confirmed. The out-of-bounds write occurs at line 29 where `calibrationTable[update.channelIndex] = update.value;` uses unchecked indexing on a fixed-size `std::array<double, 8>`. The `channelIndex` field is a `uint8_t` sourced from untrusted network input with no validation, allowing indices 0-255 to be written to an 8-element array (valid indices 0-7).

## Source

Input: `update.channelIndex` is a `uint8_t` field deserialized from the `messageBuffer` parameter via `memcpy()` at line 26. This value represents an external, untrusted input from the sensor network.

Sink: Line 29, `calibrationTable[update.channelIndex] = update.value;` writes to the array using the unchecked index.

Data flow: The deserialized `channelIndex` (0-255 range) is passed directly to `operator[]` without validation against `calibrationTable.size()` (which is 8).

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

    // Use .at() to perform bounds checking; throws std::out_of_range if index is invalid
    try {
        calibrationTable.at(update.channelIndex) = update.value;
    } catch (const std::out_of_range&) {
        // Invalid channel index; reject the update
        return;
    }
}
```

## Explanation

The fix replaces the unchecked `operator[]` access with `.at()`, which performs runtime bounds checking and throws `std::out_of_range` if the index is outside the valid range [0, 7]. This prevents the out-of-bounds write and instead gracefully rejects invalid channel indices by returning early.

The key change is on line 29 (now lines 29-33):
- **Before**: `calibrationTable[update.channelIndex] = update.value;` — no validation, undefined behavior if index >= 8
- **After**: `.at(update.channelIndex)` with exception handling — validates at runtime and rejects out-of-bounds indices

Per the C++ standard library specification, `std::array::at()` performs explicit bounds checking and throws `std::out_of_range` if the index is not less than `size()`. This is the recommended safe pattern for this vulnerability when the index comes from untrusted input.

## Behaviour changes

- **Valid channel indices (0-7)**: Unchanged. The calibration value is written to the table as before.
- **Invalid channel indices (8-255)**: Changed. Instead of writing to adjacent memory (undefined behavior/memory corruption), the update is rejected and the function returns gracefully.
- **Exception propagation**: The `std::out_of_range` exception is caught and suppressed; the caller is not notified directly but the invalid update is refused.
- **Return value**: Still void; the function returns normally on invalid indices instead of undefined behavior.
