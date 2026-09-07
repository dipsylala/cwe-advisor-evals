## Verdict

EXPLOITABLE

The vulnerability is real. The `applyFieldEdits` function accepts an untrusted offset from a network message and writes to the `std::string` using `operator[]` without bounds checking. An attacker can craft a message with an out-of-bounds offset to corrupt memory outside the allocated string buffer.

## Source

The untrusted offset originates from the network: the `edit.offset` field arrives in the `EditMessage` from a peer over the session protocol (as documented in the function's comment on lines 5-6 and the struct definition on lines 12-14). The offset is never validated against the actual size of the `record` string before being used as a write index.

## Fix

### File: StringOperatorBracketWrite.cpp

```cpp
// StringOperatorBracketWrite.cpp
//
// Applies a small set of single-character edits to an in-memory record
// buffer. Edits arrive from a peer over the session protocol as
// (offset, replacementChar) pairs describing where a previously
// escaped control character should be written back into the record.

#include <cstdint>
#include <string>
#include <vector>

struct FieldEdit {
    uint32_t offset;         // byte offset into the record, from the peer
    char replacementChar;    // unescaped character to write at that offset
};

struct EditMessage {
    std::vector<FieldEdit> edits;
};

// Applies each edit in the message to the record buffer in place.
// The record buffer was allocated earlier at the record's declared
// length and is reused across edits from the same session.
void applyFieldEdits(std::string& record, const EditMessage& message) {
    for (const FieldEdit& edit : message.edits) {
        std::size_t position = edit.offset;

        // Bounds-checked write using std::string::at(), which throws
        // std::out_of_range if position >= record.size()
        record.at(position) = edit.replacementChar;
    }
}
```

## Explanation

The fix replaces `operator[]` (which performs no bounds checking) with `.at()` (which performs a runtime bounds check and throws `std::out_of_range` if the index is >= the string's size). This is the standard C++ pattern for checked container access when the index value originates from untrusted input and is not already structurally guaranteed to be valid.

When `position >= record.size()`, `.at()` will throw an exception, causing the function to propagate the error to the caller rather than silently writing to memory outside the string's allocated region. The caller must handle this exception appropriately—logging the error, rejecting the edit message, or terminating the session depending on the application's requirements.

## Behaviour changes

- **On valid offset (0 <= offset < record.size())**: The character is written exactly as before. The fix preserves the existing behavior for in-bounds accesses.
- **On out-of-bounds offset (offset >= record.size())**: Instead of silently corrupting memory, the function now throws `std::out_of_range`. The caller must catch and handle this exception. This is a necessary behavior change: the original behavior (silent out-of-bounds write) was undefined behavior; the corrected behavior (explicit exception) is defined and prevents memory corruption. Callers should log rejected edits, audit the peer connection for protocol violations, or close the session as appropriate to the application's threat model.
