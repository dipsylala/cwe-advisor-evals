## Verdict

exploitable

## Source

`update.channelIndex` extracted from untrusted `messageBuffer` parameter via `std::memcpy()` at line 25. The `uint8_t` index can hold values 0-255, but the destination container only has 8 elements.

## Fix

**Vulnerable code (line 29):**
```cpp
calibrationTable[update.channelIndex] = update.value;
```

**Fixed code:**
```cpp
calibrationTable.at(update.channelIndex) = update.value;
```

## Explanation

The original code uses `operator[]` on `std::array`, which performs no bounds checking and produces undefined behaviour if `update.channelIndex >= 8`. Since `channelIndex` comes from untrusted network data (the message buffer), an attacker can supply any value 0-255 to write past the end of the 8-element array, corrupting adjacent memory. The fix replaces `operator[]` with `.at()`, which is the bounds-checked accessor specified in the C++ guidance. When `channelIndex >= 8`, `.at()` throws `std::out_of_range`, which halts execution and reports the error to the caller rather than corrupting memory.

## Behaviour changes

The function now throws `std::out_of_range` when an out-of-bounds index is supplied, rather than performing an out-of-bounds write. This is a correct error-handling behaviour change: the original code had a security defect; the fix enforces valid input. A caller that fails to catch the exception will see it as an unhandled exception; this is the intended outcome per the guidance: "Report a refused write to the caller rather than only logging it."
