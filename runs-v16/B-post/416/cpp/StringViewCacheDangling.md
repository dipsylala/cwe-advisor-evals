## Verdict

Exploitable

## Source

Temporary `std::string` returned by `UserProfile::displayName()` on line 19 in `remember()`.

## Fix

**Vulnerable code (line 27):**
```cpp
private:
    std::vector<std::string_view> names_;
```

**Fixed code (line 27):**
```cpp
private:
    std::vector<std::string> names_;
```

## Explanation

The vulnerability is a use-after-free caused by storing a non-owning view of a temporary. When `remember()` is called, `profile.displayName()` returns a temporary `std::string` that is passed to `push_back()`. The vector stores a `std::string_view`—merely a pointer and length into that temporary's buffer—but the temporary is destroyed at the end of the `push_back()` statement. Later, when `firstLetter()` accesses `names_[index][0]`, it dereferences a dangling pointer into freed memory, causing undefined behavior. By storing `std::string` instead of `std::string_view`, the vector owns the string data and keeps it alive for its entire lifetime, eliminating the dangling reference.

## Behaviour changes

None. The `push_back()` call automatically moves or copies the temporary into the vector storage. The `firstLetter()` function accesses the same element by index and extracts the first character—its contract and behavior remain identical, but the access now reads valid, owned memory instead of freed memory.
