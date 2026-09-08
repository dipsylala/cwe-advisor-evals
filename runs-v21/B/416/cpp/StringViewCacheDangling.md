## Verdict

Exploitable.

## Source

At line 19 in `ProfileCache::remember()`, `profile.displayName()` returns a temporary `std::string` object. This temporary is implicitly used to construct a `std::string_view` for storage in the vector at line 27.

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

The vulnerability occurs because `names_` is declared as `std::vector<std::string_view>` (line 27), storing non-owning views of strings. At line 19, `profile.displayName()` returns a temporary `std::string`. The temporary is destroyed at the end of the expression, but the `std::string_view` stored in `names_` continues to reference the now-freed memory. When `firstLetter()` accesses `names_[index][0]` at line 23, it dereferences a dangling view into deallocated memory.

The fix changes line 27 from `std::vector<std::string_view> names_;` to `std::vector<std::string> names_;`. By storing actual `std::string` objects instead of views, the cache now owns the string data directly. When `remember()` pushes the temporary return value, it is moved into the vector, and the vector maintains ownership of the string for its entire lifetime. The `firstLetter()` access at line 23 now safely accesses character data from an owned, valid string.

## Behaviour changes

None. The fix preserves the existing API and behavior: `remember()` continues to accept a `UserProfile` reference, `firstLetter()` continues to return the first character at a given index, and the indexing and character access semantics remain identical between `std::string` and `std::string_view`.

