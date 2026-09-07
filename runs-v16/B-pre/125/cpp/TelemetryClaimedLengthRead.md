## Verdict
exploitable

## Source
`length` parameter (untrusted input) combined with `offset` parameter.

## Fix

**Vulnerable code:**
```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < length; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];  // Line 12 - no bounds check on length
    }

    return checksum;
}
```

**Fixed code:**
```cpp
std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    // Validate bounds: length must not exceed frame size, and offset + length must stay in bounds
    if (length > frame.size() || offset > frame.size() - length) {
        return 0;
    }

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < length; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];
    }

    return checksum;
}
```

## Explanation
The original code validates that `offset` is within the vector's bounds but does not validate `length`. The loop iterates from `offset` to `offset + length - 1`, which can exceed the vector's allocated size if `length` is not checked. The fix adds an explicit bounds check that (1) validates `length` against `frame.size()` first to prevent unsigned arithmetic wrap-around, then (2) checks that `offset + length` does not exceed the buffer. This prevents out-of-bounds reads at line 12 where `std::vector::operator[]` performs no automatic bounds checking. The check order matters: checking `length > frame.size()` first ensures the subsequent subtraction `frame.size() - length` cannot wrap.

## Behaviour changes
none
