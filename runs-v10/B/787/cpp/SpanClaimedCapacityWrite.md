## Verdict

**Vulnerable** — Out-of-bounds write. The function validates the write index against an untrusted `claimedCapacity` parameter instead of the actual span's size, allowing an attacker to supply a larger capacity value and bypass the bounds check.

## Source

**File:** segment_writer.cpp, line 10

**Call chain:** `telemetry_encoder.cpp::encodeTelemetry()` → `segment_writer.cpp::writeSegmentByte()`

In `telemetry_encoder.cpp`, an attacker-controlled `advertisedLength` is passed as the `claimedCapacity` parameter to `writeSegmentByte()`. The function then uses this untrusted value to validate the index:

```cpp
void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= claimedCapacity) {  // ← Checks against claimed capacity, not actual span size
        return;
    }
    segment[index] = value;  // ← Line 10: out-of-bounds write if index >= segment.size()
}
```

If `claimedCapacity` is larger than `segment.size()`, an index in the range `[segment.size(), claimedCapacity)` passes the check but writes out of bounds.

## Fix

Replace the bounds check to validate against the actual span size rather than the untrusted claimed capacity:

```cpp
void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= segment.size()) {  // ← Check actual span capacity
        return;
    }

    segment[index] = value;
}
```

## Explanation

The vulnerability stems from trusting an external parameter (`claimedCapacity`) over the container's authoritative size. C++ spans (`std::span`) own their size and capacity; `segment.size()` is the only reliable upper bound for valid indices. By replacing the check with `index >= segment.size()`, the validation is now based on the actual allocated memory rather than an attacker-supplied claim.

The `claimedCapacity` parameter is rendered harmless by this fix — even if an attacker supplies a large value, the real span size enforces the actual boundary. If `claimedCapacity` has no other use (e.g., for metadata validation), it may be removable in a wider refactoring, but the minimal fix to close the vulnerability is the bounds check change shown above.

## Behaviour changes

- **Previously:** Index values up to `claimedCapacity - 1` were accepted and written to the span, even if they exceeded the span's actual size.
- **After fix:** Only index values in the range `[0, segment.size())` are accepted. Writes at or beyond `segment.size()` are silently dropped (the function returns early).
- **Error handling:** The function continues to return silently on out-of-bounds; it does not throw an exception. Callers cannot distinguish a successful write from a rejected write. For stricter error handling, consider switching to `segment.at(index)` which throws `std::out_of_range`, though this would change the function's contract and affect all callers in the `telemetry_encoder.cpp` call chain.
