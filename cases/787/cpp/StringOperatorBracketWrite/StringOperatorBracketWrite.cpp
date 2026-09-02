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

        // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
        record[position] = edit.replacementChar;
    }
}
