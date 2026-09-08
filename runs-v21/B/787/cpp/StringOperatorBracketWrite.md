## Verdict

exploitable

## Source

Line 13: `uint32_t offset` field in the `FieldEdit` struct, populated from peer message data (external, untrusted input via `EditMessage.edits` parameter at line 24).

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

        // Bounds-checked write using std::string::at() which throws
        // std::out_of_range if the position is not within the string.
        record.at(position) = edit.replacementChar;
    }
}
```

## Explanation

The vulnerability was an unchecked array index write using `operator[]` on `std::string`. The `offset` value from the untrusted peer message had no bounds validation before being used to index into the `record` string. If `position >= record.size()`, the subscript operator performs undefined behavior and writes to memory outside the allocated buffer.

The fix replaces `operator[]` with `.at()`, which performs automatic bounds checking. The `.at()` method checks if the index is within the valid range `[0, size())` and throws `std::out_of_range` if not, raising an exception that propagates to the caller. This ensures invalid offsets are rejected rather than silently corrupting memory. All valid writes continue to work identically to the original code.

## Behaviour changes

Exception handling: The function now throws `std::out_of_range` with a descriptive message if any edit offset is outside the bounds of the record string. Previously, out-of-bounds writes would result in undefined behavior (memory corruption). The caller must be prepared to handle this exception, or allow it to propagate and terminate the session. This is the intended security behavior - refusing invalid edits rather than applying them.
