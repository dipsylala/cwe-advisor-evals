## Verdict

Confirmed. `applyFieldEdits` writes to `record[position]` using `position` derived directly from the peer-controlled `edit.offset` field, with no check against `record.size()`. `std::string::operator[]` performs no bounds checking (other than the single past-the-end read case, which does not apply here since this is a write), so an attacker who sends an `offset` at or beyond the record's length causes an out-of-bounds write into or past the string's internal buffer, corrupting heap memory.

## Source

- `EditMessage::edits[].offset` (`uint32_t`, field `FieldEdit::offset`) - arrives from a peer over the session protocol, per the file's own header comment ("Edits arrive from a peer over the session protocol as (offset, replacementChar) pairs"). Fully attacker-controlled, unvalidated at the point it reaches `applyFieldEdits`.

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

        // The offset is peer-controlled and is not implicitly bounded by
        // the record's length, so it must be validated before use as an
        // index. Edits with an out-of-range offset are protocol errors
        // from the peer and are dropped rather than applied.
        if (position >= record.size()) {
            continue;
        }

        record[position] = edit.replacementChar;
    }
}
```

## Explanation

`operator[]` on `std::string` is unchecked: passing an index `>= size()` (other than exactly `size()` for a read, which returns the null terminator) is undefined behavior, and for a write it corrupts memory beyond the string's buffer rather than throwing. Because `edit.offset` is a `uint32_t` taken verbatim from an attacker-controlled protocol message, nothing upstream constrains it to the record's actual length, so the reported line was reachable with an arbitrary offset.

The fix adds an explicit bounds check, `position >= record.size()`, immediately before the indexed write, and skips any edit whose offset falls outside the record. This keeps the data flow otherwise unchanged - valid edits are still applied in place with the same `operator[]` write, preserving the function's existing behavior and performance for well-formed input - while making every out-of-range peer-supplied offset a no-op instead of an out-of-bounds write. Skipping rather than throwing avoids turning a memory-corruption bug into an unhandled-exception crash (a denial-of-service) on the same malformed input, and avoids silently resizing the record, which would change the record's declared length based on untrusted input. If the caller needs to know that a peer sent an invalid edit (e.g., to close the session or log the event), the skipped case can be surfaced by having this function report which edits were dropped, but that policy decision is separate from closing the out-of-bounds write itself.
