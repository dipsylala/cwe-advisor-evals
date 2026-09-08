## Verdict
CONFIRMED: CWE-787 out-of-bounds write at line 29. The array index `update.channelIndex` is a `uint8_t` (0–255) but the target `std::array<double, 8>` has only indices 0–7. No bounds validation exists.

## Source
The vulnerability is in line 29 of StdArrayOperatorBracketWrite.cpp:

```cpp
calibrationTable[update.channelIndex] = update.value;
```

`update.channelIndex` is read from an untrusted message buffer and used as a direct array subscript without validation. When `update.channelIndex >= 8`, this write accesses memory past the array bounds.

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

    // Validate that the channel index is within bounds before writing
    if (update.channelIndex >= calibrationTable.size()) {
        return;
    }

    calibrationTable[update.channelIndex] = update.value;
}
```

## Explanation
The fix adds a bounds check before the array write. The condition `update.channelIndex >= calibrationTable.size()` compares the untrusted index against the array's valid size (8). Using `.size()` is safer than a hardcoded literal because it couples the check to the actual array dimensions and makes the intent explicit. If the index is out of range, the function returns early without writing, preventing out-of-bounds access.
