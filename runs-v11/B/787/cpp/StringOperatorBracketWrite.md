## Verdict

Exploitable. The code performs an unchecked write using `operator[]` on a `std::string` with an index derived from untrusted peer input, permitting out-of-bounds access when the offset exceeds the string's size.

## Source

`edit.offset` from the `EditMessage` parameter. The offset arrives from a peer over the session protocol and is not validated against the `record` string's actual size before being used as an index.

## Fix

Replace the unchecked `operator[]` indexing with the bounds-checked `.at()` method:

**Vulnerable code:**
```cpp
void applyFieldEdits(std::string& record, const EditMessage& message) {
    for (const FieldEdit& edit : message.edits) {
        std::size_t position = edit.offset;
        record[position] = edit.replacementChar;  // No bounds check
    }
}
```

**Fixed code:**
```cpp
void applyFieldEdits(std::string& record, const EditMessage& message) {
    for (const FieldEdit& edit : message.edits) {
        std::size_t position = edit.offset;
        record.at(position) = edit.replacementChar;  // Bounds checked
    }
}
```

## Explanation

The C++ `std::string::operator[]` performs no bounds checking and exhibits undefined behaviour when the index exceeds the string's size, corrupting adjacent memory. The `.at()` method enforces the same bounds check and throws `std::out_of_range` if the position is out of bounds, converting the undefined-behavior write into a catchable exception. This allows the caller to handle invalid edits safely rather than silently corrupting the record or other heap state.

## Behaviour changes

The code now throws `std::out_of_range` instead of performing an out-of-bounds write when `position >= record.size()`. The caller must handle this exception; if no handler catches it, the program terminates with an uncaught exception, which is the correct safe-fail behaviour. This is a security-necessary behaviour change that prevents memory corruption.
