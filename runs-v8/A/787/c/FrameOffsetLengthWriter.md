## Verdict
CONFIRMED

## Source
```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (length > capacity) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

## Fix
```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (offset > capacity || length > capacity - offset) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

## Explanation
The original bounds check only validates that the payload length does not exceed the total buffer capacity. However, it fails to account for the offset from which writing begins. This allows `memcpy` to write beyond the buffer's bounds when `offset + length > capacity`.

The corrected check ensures that:
1. The offset itself does not exceed capacity
2. The remaining space after the offset (capacity - offset) is sufficient for the payload length

This prevents out-of-bounds writes that could corrupt memory or enable code execution.
