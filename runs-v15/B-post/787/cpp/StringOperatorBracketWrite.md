## Verdict
exploitable

## Source
`edit.offset` received in the `EditMessage` parameter from an untrusted peer over the session protocol; this value is not validated before use.

## Fix

**Vulnerable code:**
```cpp
void applyFieldEdits(std::string& record, const EditMessage& message) {
    for (const FieldEdit& edit : message.edits) {
        std::size_t position = edit.offset;
        // No bounds check; arbitrary position can write past the end of record
        record[position] = edit.replacementChar;
    }
}
```

**Fixed code:**
```cpp
void applyFieldEdits(std::string& record, const EditMessage& message) {
    for (const FieldEdit& edit : message.edits) {
        std::size_t position = edit.offset;
        // Bounds check via .at() which throws std::out_of_range if position >= record.size()
        record.at(position) = edit.replacementChar;
    }
}
```

## Explanation
The original code uses `std::string::operator[]` with an unchecked index derived from untrusted network input. The `operator[]` performs no bounds checking and exhibits undefined behaviour if the index is out of range. The fix replaces it with `.at()`, which validates that the index is within [0, record.size()) and throws `std::out_of_range` if it is not. This rejects malformed edits at the point they are applied rather than silently corrupting adjacent heap memory.

## Behaviour changes
- A write with an out-of-range offset now throws `std::out_of_range` instead of writing past the buffer's end. The caller must handle this exception or allow it to propagate and terminate the session. This is the correct behaviour for an invalid edit from an untrusted peer.
