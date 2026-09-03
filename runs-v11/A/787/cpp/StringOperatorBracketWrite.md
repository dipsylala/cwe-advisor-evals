## Verdict

The vulnerability is real. The code uses an untrusted offset from a peer to write directly into a `std::string` without bounds validation. The `operator[]` does not perform bounds checking, allowing writes beyond the string's allocated size.

## Source

`record[position] = edit.replacementChar;` at line 29 accepts an untrusted `edit.offset` (cast to `std::size_t`) without verifying it falls within the valid range `[0, record.size())`. When `position >= record.size()`, this write is out-of-bounds.

## Fix

```cpp
void applyFieldEdits(std::string& record, const EditMessage& message) {
    for (const FieldEdit& edit : message.edits) {
        std::size_t position = edit.offset;
        
        // Validate position is within bounds before writing
        if (position >= record.size()) {
            continue;  // Skip invalid edits
        }
        
        record[position] = edit.replacementChar;
    }
}
```

Alternatively, throw an exception for invalid offsets:

```cpp
void applyFieldEdits(std::string& record, const EditMessage& message) {
    for (const FieldEdit& edit : message.edits) {
        std::size_t position = edit.offset;
        
        if (position >= record.size()) {
            throw std::out_of_range("Edit offset exceeds record size");
        }
        
        record[position] = edit.replacementChar;
    }
}
```

## Explanation

CWE-787 (Out-of-bounds Write) occurs when data from an untrusted source (the peer-supplied `edit.offset`) is used as an array index without validation. The `std::string::operator[]` provides direct memory access without bounds checking—unlike `.at()`, which would throw `std::out_of_range`.

The fix adds a bounds check before each write: if the offset is invalid, either skip the edit or raise an exception. Skipping silently preserves availability; throwing fails fast and alerts the caller to protocol violations. The choice depends on whether invalid edits should be treated as a recoverable application error or a fatal protocol breach.
