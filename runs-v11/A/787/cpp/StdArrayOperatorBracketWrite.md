## Verdict

The vulnerability is real. The code performs an out-of-bounds write via unchecked array indexing.

## Source

The vulnerability originates in the `applyCalibrationUpdate` function parameter `messageBuffer`, which is parsed into a `CalibrationUpdateMessage` struct. The `channelIndex` field is extracted without validation and used directly as an array index.

## Fix

Add a bounds check on `update.channelIndex` before the array access. The corrected statement is:

```cpp
// Add bounds validation before array access
if (update.channelIndex < calibrationTable.size()) {
    calibrationTable[update.channelIndex] = update.value;
}
```

Alternatively, use the safe `.at()` method which throws an exception on out-of-bounds access:

```cpp
try {
    calibrationTable.at(update.channelIndex) = update.value;
} catch (const std::out_of_range&) {
    // Log error or handle invalid channel index
}
```

## Explanation

The `calibrationTable` is a fixed-size `std::array<double, 8>` with valid indices 0–7. The `channelIndex` field is a `uint8_t`, which can hold values 0–255. Without bounds checking, passing a `channelIndex` value >= 8 causes the array subscript operator `[]` to access memory beyond the array boundary, resulting in an out-of-bounds write.

The fix adds explicit validation: either check `update.channelIndex < calibrationTable.size()` before access, or use `.at()`, which provides built-in bounds checking and throws `std::out_of_range` for invalid indices. This prevents writes to unintended memory locations.
