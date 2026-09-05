## Verdict

Exploitable. The `channelIndex` field parsed from external input is used as an array subscript with no bounds check, permitting writes beyond the 8-element `calibrationTable`.

## Source

`messageBuffer` - external input untrusted. Parsed via `std::memcpy()` into `update.channelIndex` (uint8_t, range 0–255).

## Fix

**Vulnerable code (line 29):**
```cpp
calibrationTable[update.channelIndex] = update.value;
```

**Fixed code:**
```cpp
if (update.channelIndex >= calibrationTable.size()) {
    return;
}
calibrationTable[update.channelIndex] = update.value;
```

## Explanation

The original code uses `operator[]` on `std::array`, which performs no bounds checking (undefined behaviour if the index is out of range). The `channelIndex` field is untrusted external data with no validation to ensure it stays within [0, 7]. A sender supplying `channelIndex >= 8` causes a write past the end of the allocation, corrupting adjacent memory. The fix adds an explicit bounds check using `calibrationTable.size()` before the write, rejecting invalid channels by returning early. This follows the C++ guidance to validate every write against the destination's actual capacity.

## Behaviour changes

Function now returns silently when `channelIndex >= 8` instead of writing out of bounds. This is a safe defensive change: invalid calibration updates are rejected rather than corrupting memory. The caller receives no signal (the function still returns void), but the corruption is prevented and the calibration table state remains sound.
