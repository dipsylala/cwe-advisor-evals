## Verdict
CONFIRMED — Use-after-free via dangling `std::string_view`.

## Source
The `ProfileCache::remember()` method caches the result of `profile.displayName()` as a `std::string_view`. Since `displayName()` returns a temporary `std::string`, the temporary is destroyed at the end of the statement, leaving the `std::string_view` as a dangling pointer. Subsequent calls to `firstLetter()` dereference this invalid memory.

## Fix

### File: StringViewCacheDangling.cpp

```cpp
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

class UserProfile {
public:
    std::string displayName() const {
        return first_ + " " + last_;
    }

    std::string first_;
    std::string last_;
};

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
The fix changes `std::vector<std::string_view> names_` to `std::vector<std::string> names_` on line 27. 

`std::string_view` is a non-owning string reference useful for passing strings without allocation, but it must not outlive the underlying string. Since `displayName()` returns a temporary, storing it as a view creates a dangling pointer.

By storing `std::string` directly, the vector takes ownership of the string data via move construction. The temporary from `displayName()` is moved into the vector element, and the vector now owns and manages the lifetime of the cached names. Subsequent accesses to `firstLetter()` safely dereference valid memory.
