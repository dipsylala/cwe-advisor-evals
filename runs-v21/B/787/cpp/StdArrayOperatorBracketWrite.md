## Verdict

Confirmed. An untrusted `uint8_t` from the network message is used to index a fixed-size array without bounds validation, permitting out-of-bounds writes.

## Source

The `messageBuffer` parameter receives untrusted sensor-network data. The binary message is deserialized via `memcpy()` into a `CalibrationUpdateMessage` structure, extracting a `uint8_t channelIndex` field that ranges over 0–255 in principle but is never validated against the array's actual size.

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

The vulnerability arises because `std::array::operator[]` performs no runtime bounds check and produces undefined behavior when subscripted out of range. The fix validates that `channelIndex` is less than the array's size (8) before using it as a subscript. This follows the C++ remediation guidance: "Reserve `operator[]` for an index already validated or structurally guaranteed." The validation is positioned immediately before the sink and returns early on an invalid index, matching the existing error-handling style of the function (which already validates message length and null pointer). After this fix, `operator[]` is called only with an already-validated index, and the write cannot exceed the array bounds.

## Behaviour changes

The function now rejects calibration updates with an out-of-range `channelIndex` by returning early without modifying the calibration table. Requests with channel indices 8–255 fail silently rather than corrupting memory. Valid inputs (0–7) continue to work identically. This is a defensive change with no impact on legitimate callers and no observable side effects on success paths.
