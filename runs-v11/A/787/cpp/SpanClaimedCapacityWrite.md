## Verdict

Out-of-bounds write at line 10. The vulnerability bounds-check uses an untrusted claimed capacity parameter instead of the actual span size. An attacker can provide a claimed capacity larger than the span's true size, causing an out-of-bounds write when the index falls within the claimed range but exceeds the span bounds.

## Source

```cpp
void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= claimedCapacity) {
        return;
    }

    segment[index] = value;  // Line 10: OOB write if claimedCapacity > segment.size()
}
```

The vulnerability: the guard at line 6 checks `index >= claimedCapacity`, but `claimedCapacity` is an untrusted parameter that may exceed `segment.size()`. If index is between `segment.size()` and `claimedCapacity`, the bounds check passes but the array access exceeds the span's actual bounds.

## Fix

```cpp
void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= segment.size()) {
        return;
    }

    segment[index] = value;
}
```

Change the bounds check from `if (index >= claimedCapacity)` to `if (index >= segment.size())`. This ensures the index is validated against the actual allocated span size, not a caller-supplied capacity claim that may be incorrect or malicious.

## Explanation

CWE-787 occurs when a buffer write is not properly validated against the buffer's true size. In this case, the function receives both the actual span and a separate `claimedCapacity` parameter. The code trusts the claimed capacity for bounds checking, but a caller can provide any value. The span object itself carries its true size via `.size()`, which should be the authoritative bound. By checking `index >= segment.size()` instead of against the unchecked parameter, the write is guaranteed to stay within allocated memory.
