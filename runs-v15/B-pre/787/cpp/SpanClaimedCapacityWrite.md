## Verdict

**Confirmed.** The code writes to a span without validating the index against the span's actual size. Instead, it validates against an untrusted external value (`claimedCapacity`) that may be larger than the actual buffer, enabling out-of-bounds write.

## Source

File: `segment_writer.cpp`, line 10
```cpp
segment[index] = value;
```

The vulnerability exists in the data flow:
1. `encodeTelemetry()` receives `advertisedLength` from external input (packet header, protocol frame, or similar)
2. It passes this untrusted value as `claimedCapacity` to `writeSegmentByte()`
3. `writeSegmentByte()` validates `index >= claimedCapacity` (line 6) but then writes to `segment[index]` without checking against the actual span size
4. `std::span::operator[]` performs no bounds check and is undefined behaviour out of range

The check validates against the sender's claim, not the actual destination capacity.

## Fix

Replace the bounds check to validate against the span's actual size:

```cpp
void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= segment.size()) {
        return;
    }

    segment[index] = value;
}
```

## Explanation

The vulnerability arises from validating an index against an untrusted external capacity claim rather than the actual span capacity. The `claimedCapacity` parameter represents a value from an untrusted source (packet header, file metadata, network message) and cannot be trusted to match the actual buffer size.

`std::span` tracks the true allocated size in `.size()`. By checking `index >= segment.size()` instead of `index >= claimedCapacity`, the code ensures the write stays within the actual buffer bounds. `std::span::operator[]` provides no protection, so the validation must occur before use.

The fix leaves the `claimedCapacity` parameter in place to avoid breaking the call site signature, but correctly disregards its value in favour of the span's own capacity.

## Behaviour changes

- Writes with `index >= segment.size()` will now be rejected (return early) rather than written out of bounds
- If `segment.size() < claimedCapacity`, fewer writes will be accepted (stricter bounds), preventing overflow
- The function will no longer corrupt memory adjacent to the span when an attacker inflates the advertised length
