## Verdict
Exploitable

## Source
Line 19: `profile.displayName()` returns a temporary `std::string` by value

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
The vulnerability occurs because `std::string_view` is a non-owning view that holds a pointer to external memory. When `remember()` receives `profile.displayName()` (a temporary string), the view is created pointing to that temporary, but the temporary is destroyed immediately after `push_back()` completes. Subsequently, accessing the view through `names_[index][0]` dereferences a dangling pointer to freed memory. Changing the container to `std::vector<std::string>` makes the vector the owner of the strings, ensuring they remain valid for the lifetime of the vector. The implicit conversion from `std::string` to `std::string_view` during temporary construction still occurs, but now it constructs a `std::string` in-place via the vector's push_back, which owns and extends the string's lifetime.

## Behaviour changes
None. The `push_back()` call will accept a temporary `std::string` and construct it into the vector with the same behavior as before; the only difference is that the vector now owns the stored strings rather than views of destroyed temporaries. Return values, discard behavior, and error handling remain identical.
