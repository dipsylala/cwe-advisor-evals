## Verdict

The cache stores `std::string_view` references to temporary strings that are destroyed after `remember()` returns, creating a use-after-free vulnerability when `firstLetter()` accesses the dangling views.

## Source

```cpp
class ProfileCache {
public:
    void remember(const UserProfile& profile) {
        names_.push_back(profile.displayName());  // displayName() returns a temporary std::string
    }

    char firstLetter(std::size_t index) const {
        return names_[index][0];  // accessing dangling string_view
    }

private:
    std::vector<std::string_view> names_;  // non-owning views
};
```

The problem: `displayName()` returns a temporary `std::string`. A `std::string_view` to this temporary is stored in `names_`. When `remember()` returns, the temporary is destroyed, leaving `names_` with dangling pointers. Later calls to `firstLetter()` dereference freed memory.

## Fix

Change the cache to own the strings, not merely reference them:

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
    std::vector<std::string> names_;  // change from std::string_view to std::string
};
```

## Explanation

`std::string_view` is a non-owning view—a lightweight reference to existing string data. It is safe only when the underlying string remains alive for the entire lifetime of the view. In this case, `displayName()` returns a temporary string that is destroyed immediately after `push_back()` copies its address into the view. The fix is to store `std::string` instead, which owns and persists the string data within the vector. This eliminates the dangling reference and makes the cache safe.
