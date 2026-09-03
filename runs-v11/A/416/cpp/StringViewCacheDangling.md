## Verdict
Real issue — use-after-free via dangling string_view pointer.

## Source
The `remember()` method at line 19 stores `profile.displayName()` (a temporary `std::string`) as a `std::string_view` in the vector. The temporary string is destroyed when `remember()` returns, leaving the `string_view` with a dangling pointer. When `firstLetter()` accesses `names_[index][0]` at line 23, it dereferences this dangling pointer.

## Fix
Change the member variable from `std::vector<std::string_view> names_` to `std::vector<std::string> names_`:

```cpp
class ProfileCache {
public:
    void remember(const UserProfile& profile) {
        names_.push_back(profile.displayName());
    }

    char firstLetter(std::size_t index) const {
        return names_[index][0];
    }

private:
    std::vector<std::string> names_;
};
```

## Explanation
`std::string_view` is a non-owning view of string data and must not outlive the string it points to. Storing a `string_view` to a temporary returned from `displayName()` creates a dangling pointer. The fix stores full `std::string` objects owned by the vector, so the data persists for the entire lifetime of the cache entry. This eliminates the use-after-free while preserving the intended caching behavior.
