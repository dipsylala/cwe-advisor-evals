## Verdict

Exploitable. The `channelIndex` field is read from untrusted external input (the message buffer) and used directly as an array index without bounds validation. Since `channelIndex` is a `uint8_t` (range 0-255) and the `calibrationTable` array has only 8 elements (indices 0-7), any message with `channelIndex >= 8` will write out of bounds, corrupting adjacent stack memory.

## Source

Untrusted data flow originates from the message buffer parameter to `applyCalibrationUpdate()`. The `messageBuffer` is memcpy'd into the stack-allocated `update` structure at line 26. The `channelIndex` field is extracted from this untrusted external input.

## Fix

Vulnerable code (line 29):
```cpp
calibrationTable[update.channelIndex] = update.value;
```

Fixed code:
```cpp
if (update.channelIndex >= calibrationTable.size()) {
    return;
}
calibrationTable[update.channelIndex] = update.value;
```

## Explanation

The fix validates that `channelIndex` stays within the bounds of the 8-element `calibrationTable` array before using it as an array index. The bounds check `update.channelIndex >= calibrationTable.size()` compares the untrusted index against the array's actual capacity (8) and rejects any update with an out-of-range channel number by returning early. This prevents the out-of-bounds write and the subsequent corruption of stack memory. The check uses `size()` rather than a hardcoded constant to ensure maintainability if the array size is changed in the future.

## Behaviour changes

The function now returns without storing the calibration value if `channelIndex` is >= 8. Previous behavior silently corrupted memory; the fixed version silently rejects the update. No exception is thrown or error is returned to the caller. If caller notification of rejection is required, the function signature would need to be changed to return `bool` or `int`, but the current void return type allows only silent rejection. The return type and formal parameters remain unchanged. The `if` statement uses only the existing `calibrationTable` object and the untrusted `update.channelIndex` value; no new parameters or variables are introduced beyond the condition itself.
