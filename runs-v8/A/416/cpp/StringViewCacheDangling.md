## Verdict

Use-after-free confirmed. The `ProfileCache` class stores `std::string_view` objects that refer to temporary strings destroyed after `remember()` returns, creating dangling references accessed later by `firstLetter()`.

## Source

Line 19: `names_.push_back(profile.displayName());` stores a `std::string_view` pointing to the return value of `displayName()`, which is a temporary `std::string` object. The temporary is destroyed at the end of the statement, but the view remains in the vector.

Line 23: `return names_[index][0];` dereferences the dangling view, reading freed memory.

## Fix

Change line 27 from:
```cpp
std::vector<std::string_view> names_;
```

to:
```cpp
std::vector<std::string> names_;
```

No other changes needed; the rest of the code remains valid because `std::vector<std::string>` owns the strings and keeps them alive for the lifetime of the cache.

## Explanation

`std::string_view` is a non-owning view into string data. When storing views in a container, the underlying data must remain valid for the lifetime of the container. The temporary `std::string` returned by `displayName()` is destroyed immediately after `push_back()` returns, leaving the `std::string_view` with a dangling pointer.

Storing `std::string` objects instead makes the vector own and manage the string lifetime, eliminating the dangling reference. The accessor `firstLetter()` works unchanged because `std::string` supports indexing just as `std::string_view` does.
