## Verdict

CWE-787 (Out-of-bounds Write) confirmed. The vulnerability is a missing bounds check when using `operator[]` on a `std::string`.

## Source

At line 29, `record[position]` writes to the string without validating that `position` is within the valid range `[0, record.size())`. Since `position` is derived from untrusted peer data (`edit.offset`), an attacker can supply an offset larger than the string's size to trigger out-of-bounds access.

## Fix

```cpp
void applyFieldEdits(std::string& record, const EditMessage& message) {
    for (const FieldEdit& edit : message.edits) {
        std::size_t position = edit.offset;

        // Bounds check: only write if position is within the string's valid range
        if (position < record.size()) {
            record[position] = edit.replacementChar;
        }
    }
}
```

## Explanation

`std::string::operator[]` does not perform bounds checking — it exhibits undefined behavior when the index is out of range. Using `operator[]` directly on untrusted offsets from peer data creates an out-of-bounds write vulnerability.

The fix adds a bounds check using `record.size()` before any write. The write is performed only if the offset is strictly less than the string's length, staying within the valid index range. This ensures that edits at invalid positions are silently ignored rather than corrupting memory.

Alternative approaches include using `at()` (which throws `std::out_of_range`), but silently skipping invalid edits is more resilient in a protocol handler that may receive malformed messages from untrusted peers.
