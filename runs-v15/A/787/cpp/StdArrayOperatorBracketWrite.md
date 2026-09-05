## Verdict

The code is vulnerable to out-of-bounds write. The array `calibrationTable` has exactly 8 elements (indices 0–7), but the index `update.channelIndex` is a `uint8_t` that can hold any value from 0–255 without constraint. When a message arrives with `channelIndex` greater than 7, the write at line 29 exceeds the array bounds.

## Source

```cpp
// Line 29: unchecked index into fixed-size array
calibrationTable[update.channelIndex] = update.value;
```

The source of the index is deserialized from the network message without validation. The struct member `update.channelIndex` (of type `uint8_t`) can hold any octet value, but the code assumes it falls within the array's valid range.

## Fix

Add a bounds check immediately after deserializing the message and before the array write:

```cpp
void applyCalibrationUpdate(const uint8_t* messageBuffer, size_t messageLength) {
    if (messageBuffer == nullptr || messageLength < sizeof(CalibrationUpdateMessage)) {
        return;
    }

    CalibrationUpdateMessage update{};
    std::memcpy(&update, messageBuffer, sizeof(update));

    // Validate index before write
    if (update.channelIndex >= calibrationTable.size()) {
        return;
    }

    calibrationTable[update.channelIndex] = update.value;
}
```

## Explanation

The fix validates that `update.channelIndex` is within the valid range `[0, calibrationTable.size())` before performing the array write. Using `calibrationTable.size()` (which returns 8) makes the check self-documenting and maintainable if the array size changes. If the index is out of bounds, the function returns early without modifying the array.

This prevents an attacker-controlled network message from writing to memory outside the intended array buffer, eliminating the out-of-bounds write vulnerability.
