## Verdict

Confirmed. `channelIndex` is an attacker-controlled `uint8_t` (range 0-255) read directly from the network message and used unchecked as the index into `calibrationTable`, a `std::array<double, 8>`. Any `channelIndex` value of 8-255 causes `operator[]` to write 8 bytes past (or otherwise outside) the backing array, corrupting adjacent memory.

## Source

`applyCalibrationUpdate`'s `messageBuffer` parameter (the sensor-network message) supplies `update.channelIndex` via the `std::memcpy` at line 26. The function validates only the buffer's overall length against `sizeof(CalibrationUpdateMessage)`; it never validates that `channelIndex` falls within `calibrationTable`'s bounds before using it as an index.

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

`calibrationTable` has a fixed capacity of 8 elements, but `channelIndex` is an unvalidated `uint8_t` that can carry any value from 0 to 255. `std::array::operator[]` performs no bounds checking (unlike `.at()`, which throws `std::out_of_range`), so any `channelIndex` of 8 or higher writes an 8-byte `double` outside the array's backing storage, corrupting whatever static data follows it.

The fix adds an explicit range check (`update.channelIndex >= calibrationTable.size()`) before the indexed write, rejecting the update and returning early when the channel index is out of bounds. This is the correct check because `channelIndex` is a message field with an application-defined valid range (0-7, matching the 8-channel sensor bank), not a value that could reasonably take any `uint8_t` value; the length check already performed at line 21 only guarantees the buffer is large enough to decode the struct, it says nothing about the decoded field's value. Switching to `calibrationTable.at(update.channelIndex)` was considered but rejected: an out-of-range channel index in a calibration update is an expected occurrence on a live sensor network, and letting it throw an uncaught exception (and terminate the process) is a worse failure mode for embedded/control-loop code than dropping the single bad update, which the explicit check allows.
