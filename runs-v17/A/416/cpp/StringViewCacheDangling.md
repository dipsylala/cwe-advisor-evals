## Verdict
Use-after-free confirmed at line 23. The `std::string_view` stored at line 19 references a temporary string that is destroyed at the end of the statement, leaving a dangling pointer that is dereferenced in line 23.

## Source
```cpp
class ProfileCache {
public:
    void remember(const UserProfile& profile) {
        names_.push_back(profile.displayName());  // Stores string_view to temporary
    }

    char firstLetter(std::size_t index) const {
        return names_[index][0];  // Dereferences dangling pointer
    }

private:
    std::vector<std::string_view> names_;  // Owns string_view objects
};
```

The `displayName()` method returns a temporary `std::string` by value. Storing this temporary as a `std::string_view` creates a dangling reference once the temporary is destroyed.

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
The core issue is that `std::string_view` is a non-owning view—a span of data that must remain valid elsewhere. When `profile.displayName()` returns a temporary `std::string`, that string is constructed, referenced by the view, and then destroyed at the end of the expression. The view becomes dangling.

The fix changes `names_` from `std::vector<std::string_view>` to `std::vector<std::string>`. Now:
- The vector owns copies of the strings returned by `displayName()`
- Each string persists for the vector's lifetime
- `firstLetter()` safely dereferences valid data

This is the standard defense against dangling views: prefer value semantics (owning containers) over reference semantics when the referenced data is temporary or has an uncertain lifetime.
