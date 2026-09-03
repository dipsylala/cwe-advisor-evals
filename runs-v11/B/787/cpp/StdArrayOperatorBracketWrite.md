## Verdict

Exploitable.

## Source

`messageBuffer`, an untrusted network buffer passed to `applyCalibrationUpdate()`. The `channelIndex` field is extracted via `std::memcpy()` from this untrusted input without validation.

## Fix

**Vulnerable code:**

```cpp
CalibrationUpdateMessage update{};
std::memcpy(&update, messageBuffer, sizeof(update));

// SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
calibrationTable[update.channelIndex] = update.value;
```

**Fixed code:**

```cpp
CalibrationUpdateMessage update{};
std::memcpy(&update, messageBuffer, sizeof(update));

if (update.channelIndex >= calibrationTable.size()) {
    return;
}
calibrationTable[update.channelIndex] = update.value;
```

## Explanation

The vulnerability occurs because `update.channelIndex` is a `uint8_t` extracted from untrusted network input without validation, but `calibrationTable` is a fixed-size `std::array<double, 8>` with only 8 valid indices (0–7). A `uint8_t` can hold values 0–255; writing to index 8 or higher causes an out-of-bounds write that corrupts adjacent memory. The fix adds a bounds check before the write, comparing the index against `calibrationTable.size()` and rejecting out-of-range values by returning early. This prevents the out-of-bounds access and aligns with the C++ guidance to validate indices against the container's actual size before performing an `operator[]` write.

## Behaviour changes

The function now returns early if `update.channelIndex >= calibrationTable.size()`, rejecting invalid channel indices. Callers receive the same void return and cannot distinguish between a valid update and a rejected one; this is an existing API limitation preserved by the fix. The actual behaviour change is that out-of-range indices are now rejected rather than causing undefined behaviour (memory corruption).
