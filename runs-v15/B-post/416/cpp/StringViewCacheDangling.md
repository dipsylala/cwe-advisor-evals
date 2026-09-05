## Verdict

Use-after-free via dangling `std::string_view` stored in a container that outlives the temporary string it references.

## Source

Line 19: `names_.push_back(profile.displayName());`

The `displayName()` method returns a temporary `std::string` by value. This temporary is destroyed at the end of the expression.

## Fix

**Vulnerable code:**
```cpp
private:
    std::vector<std::string_view> names_;
```

**Fixed code:**
```cpp
private:
    std::vector<std::string> names_;
```

## Explanation

The vulnerability occurs because `names_` stores `std::string_view` objects that point to the data of temporary `std::string` objects returned by `displayName()`. Once `push_back()` completes, the temporary string is destroyed, leaving the string_view pointing to freed memory. When `firstLetter()` later accesses `names_[index][0]`, it dereferences this dangling view, reading memory that may have been reallocated.

The fix is to store the actual `std::string` objects directly in the vector instead of views into them. This transfers ownership of the string data from the temporary to the container. The vector now owns the string lifetime, and the memory remains valid for the entire duration the vector holds the entry. The `std::string_view` pattern is only safe when the view's lifetime is strictly bounded by the lifetime of the object it references; storing a view in a container that can outlive the temporary violates this invariant.

## Behaviour changes

The fixed code stores complete string copies in the vector instead of non-owning views. This:
- Eliminates the use-after-free at line 23 by ensuring the string data is valid whenever the vector holds it
- Increases memory overhead slightly (each string is stored in the vector rather than referenced), but guarantees memory safety
- Does not change the observable behavior of `firstLetter()` - it still returns the first character of the cached name at the given index
