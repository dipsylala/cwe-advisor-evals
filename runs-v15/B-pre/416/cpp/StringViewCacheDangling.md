## Verdict

Confirmed use-after-free: the `ProfileCache` stores `std::string_view` objects pointing to temporary strings returned by `UserProfile::displayName()`. When the temporary strings are destroyed at the end of the `remember()` call, the views become dangling pointers. Subsequent accesses in `firstLetter()` read through invalid memory.

## Source

Line 19: `names_.push_back(profile.displayName());` stores a view of a temporary string.

Line 8-10: `displayName()` returns a temporary `std::string` created by value concatenation.

Line 23: `return names_[index][0];` dereferences the dangling view.

Data flow: `displayName()` creates a temporary std::string → stored as std::string_view in vector → temporary destroyed → view becomes dangling → dereferenced in firstLetter().

## Fix

Change the storage container from `std::vector<std::string_view>` to `std::vector<std::string>` to own the strings instead of borrowing views into temporaries.

**Original code (line 27):**
```cpp
std::vector<std::string_view> names_;
```

**Fixed code:**
```cpp
std::vector<std::string> names_;
```

No other changes are needed. The `remember()` and `firstLetter()` methods work correctly with owned strings: when a temporary string is pushed into a `vector<std::string>`, it is copied into the vector's storage and remains valid. The indexing and character access in `firstLetter()` now operate on valid, owned strings.

## Explanation

The vulnerability arises from storing non-owning views of temporaries. When `profile.displayName()` returns a temporary string, `push_back()` stores only a view of its buffer, not the string itself. The temporary is destroyed at the end of the full expression, leaving the view pointing to freed memory. Later accesses through `names_[index]` dereference that dangling pointer.

Changing to `vector<string>` inverts the lifetime relationship: the vector now owns copies of the display names, so they persist as long as the cache exists. This is the standard C++ pattern for caching: own the cached data or borrow only when the owner's lifetime is explicitly bounded (e.g., a parameter with function scope).

The taint sink (line 23, dereferencing through `names_[index]`) is eliminated because the strings are no longer dangling.

## Behaviour changes

The `ProfileCache` now stores full strings instead of views, increasing memory usage slightly (each cached name requires allocation and copy). Semantically, the behaviour is identical: `firstLetter(i)` still returns the first character of the i-th cached display name. The change is a correctness fix with no observable change to the external contract of the methods.
