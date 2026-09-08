## Verdict

Exploitable. Confidence: high.

`FieldEdit.offset` arrives from a peer over the session protocol and is used, unvalidated, as an index into `record` via `std::string::operator[]`. `operator[]` on `std::string` performs no bounds check; per the C++ standard it is undefined behaviour to use it with an index `>= size()`. A peer that sends an offset at or beyond the record's length causes an out-of-bounds write.

## Source

- Source: `EditMessage::edits` (peer-supplied, arrives over the session protocol) - specifically `FieldEdit.offset` (`uint32_t`), which is attacker-controlled and never validated against the destination buffer's size.
- Flow: `applyFieldEdits` iterates `message.edits`; each `edit.offset` is copied into `std::size_t position` with no range check.
- Sink (line 29): `record[position] = edit.replacementChar;` - `std::string::operator[]` write with an unchecked, externally-controlled index.

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

        // Bounds-checked write: throws std::out_of_range instead of
        // performing an out-of-bounds write when the peer-supplied
        // offset is not within the record's actual size.
        record.at(position) = edit.replacementChar;
    }
}
```

## Explanation

The offset driving the write is peer-controlled and was never checked against `record`'s actual size before being used to index into it. Replacing `record[position]` with `record.at(position)` swaps the unchecked `operator[]` for `std::string`'s bounds-checked accessor: `.at()` validates `position` against `record.size()` internally and throws `std::out_of_range` instead of writing past the end (or before the start) of the buffer. This closes the out-of-bounds write while keeping the write itself - the character is still stored at the caller-declared offset for every valid edit - so the fix is the minimal change that satisfies the sink's existing contract (in-place mutation of `record`, one edit per loop iteration) for legitimate offsets and refuses the illegitimate ones instead of corrupting adjacent memory.

## Behaviour changes

- An offset that is within `record.size()` behaves exactly as before: the character is written in place, no observable change.
- An offset at or beyond `record.size()` previously produced undefined behaviour (a silent out-of-bounds write - possible memory corruption or a crash with no defined failure signal). It now throws `std::out_of_range` from `applyFieldEdits`, which is unhandled in this function and propagates to the caller. This is the required consequence of closing the weakness: per the CWE-787 C++ guidance, a refused write must be reported to the caller rather than swallowed, and `std::string` has no non-throwing bounds-checked write to fall back to. Callers of `applyFieldEdits` that did not previously expect an exception from this call now need to catch `std::out_of_range` (or accept propagation/termination) for sessions that send an out-of-range offset.
- The loop was not transactional before the fix and still is not: if an out-of-range offset appears partway through `message.edits`, edits already applied earlier in the same call remain applied and the remaining edits in the message are not attempted, because the exception unwinds out of the loop. This partial-application behaviour is unchanged from the original code's control flow (the original would have kept iterating with undefined results instead of stopping); it is called out here because the fix changes how - and when - that flow stops.
- Verification: no C++ compiler was reachable in this environment (`g++`, `clang++`, `c++`, `cl` were all absent from PATH), so this was checked by manual review instead of compilation. `std::string::at(size_type)` is a standard member returning `char&` (assignable, matching the prior `operator[]` usage), and the argument type at the call site, `std::size_t position`, matches `std::string::size_type` on all mainstream standard library implementations. `<string>` was already included; no new include, symbol, or dependency was introduced. No other line in the file was changed.
