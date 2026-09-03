## Verdict

Exploitable. The cache stores non-owning string views of temporary strings that are destroyed immediately after storage, leaving the views dangling. Line 23 dereferences one of these dangling views, performing a use-after-free.

## Source

Line 19: `profile.displayName()` returns a temporary `std::string`.

## Sink

Line 23: `return names_[index][0];` dereferences a `std::string_view` stored in the cache.

## Fix

**Vulnerable code (line 27):**
```cpp
std::vector<std::string_view> names_;
```

**Fixed code:**
```cpp
std::vector<std::string> names_;
```

## Explanation

The vulnerability occurs because `remember()` passes a temporary `std::string` from `displayName()` to `push_back()` where it is implicitly converted to `std::string_view`. The vector stores only the non-owning view (a pointer and size into the temporary's buffer). The temporary is destroyed at the end of line 19, leaving the stored `std::string_view` with a dangling pointer. When `firstLetter()` later accesses `names_[index][0]`, it dereferences memory that was freed and may have been reused by the allocator.

Changing the vector to store `std::string` instead of `std::string_view` makes the vector own the string data. The temporary is move-constructed into the vector on line 19, and the string data remains valid for as long as the vector is alive, eliminating the use-after-free.

## Behaviour changes

None. The move-construction of the temporary `std::string` into the vector is equally efficient as the original implicit conversion to `std::string_view`. The return type of `firstLetter()` remains `char` and all call signatures stay identical. The vector's size and access patterns are unchanged.
