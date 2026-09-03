## Verdict
Exploitable

## Source
`edit.offset` from `message.edits` - untrusted peer input received over the session protocol as part of the `EditMessage` structure passed to `applyFieldEdits()`.

## Fix

**Vulnerable code:**
```cpp
void applyFieldEdits(std::string& record, const EditMessage& message) {
    for (const FieldEdit& edit : message.edits) {
        std::size_t position = edit.offset;

        // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
        record[position] = edit.replacementChar;  // No bounds check
    }
}
```

**Fixed code:**
```cpp
void applyFieldEdits(std::string& record, const EditMessage& message) {
    for (const FieldEdit& edit : message.edits) {
        std::size_t position = edit.offset;

        // Use .at() to validate the index against the string's actual size
        record.at(position) = edit.replacementChar;
    }
}
```

## Explanation
The original code uses `operator[]` on `std::string`, which does not perform bounds checking and exhibits undefined behaviour when the index exceeds the string's size. Because `position` is derived directly from untrusted peer input (`edit.offset`), an attacker can supply an offset beyond the record's allocated size, causing a write past the end of the buffer and corrupting adjacent memory. The fix replaces `operator[]` with `.at()`, which performs bounds checking and throws `std::out_of_range` if the index is invalid. This enforces that every write stays within the record's actual capacity and fails safely rather than silently corrupting memory.

## Behaviour changes
- `.at()` throws `std::out_of_range` on out-of-bounds access, whereas `operator[]` exhibits undefined behaviour.
- The function signature remains `void`, but now the function can propagate the exception to the caller rather than silently corrupting memory.
- The caller's error handling must be adapted to catch and respond to `std::out_of_range` exceptions instead of silently accepting corrupted edits. This is a necessary trade-off: failed writes must be reported to the caller rather than hidden.
- No other behavioural changes; the write operation itself is identical for valid indices.
