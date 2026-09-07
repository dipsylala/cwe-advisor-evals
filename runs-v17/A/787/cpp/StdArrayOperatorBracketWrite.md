## Verdict

**CONFIRMED**

The code performs an unchecked array write via `operator[]` on a fixed-size `std::array<double, 8>` using an untrusted index from the deserialized message. The `channelIndex` field is a `uint8_t`, which can hold values 0–255, but the array only has 8 elements (valid indices 0–7). Any message with `channelIndex >= 8` triggers an out-of-bounds write.

## Source

**File:** `StdArrayOperatorBracketWrite.cpp`  
**Lines:** 20–30

The vulnerability is in the `applyCalibrationUpdate()` function:
- **Message parsing** (line 26): `std::memcpy(&update, messageBuffer, sizeof(update))` deserializes an untrusted `CalibrationUpdateMessage` struct containing a `uint8_t channelIndex`.
- **Unchecked sink** (line 29): `calibrationTable[update.channelIndex] = update.value` writes to the array using the untrusted index without bounds validation.

The function validates message buffer length (line 21) to prevent underruns during deserialization, but does not validate the semantic correctness of the deserialized fields—specifically, that `channelIndex` falls within array bounds.

## Fix

Validate `channelIndex` against array bounds before writing. Reject out-of-bounds updates early.

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

    // Validate that channelIndex is within array bounds before writing.
    if (update.channelIndex >= calibrationTable.size()) {
        return;
    }

    calibrationTable[update.channelIndex] = update.value;
}
```

## Explanation

The fix adds a bounds check (line 31–33) that rejects any message whose `channelIndex` is outside the valid range [0, 7]. This follows the established pattern of early validation in the function: just as the buffer-length check (line 21) validates the transport layer, the bounds check validates the semantic correctness of the message payload before use.

The comparison `update.channelIndex >= calibrationTable.size()` is safe and idiomatic in C++:
- `calibrationTable.size()` returns 8 (a `size_t`).
- `update.channelIndex` (a `uint8_t`) is implicitly promoted to `size_t` for comparison.
- Any out-of-bounds index triggers the guard and returns early.

This eliminates the out-of-bounds write without changing the function's interface or requiring exception handling.
