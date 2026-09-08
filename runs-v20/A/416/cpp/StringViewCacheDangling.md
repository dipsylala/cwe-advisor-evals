## Verdict

Confirmed. `ProfileCache::remember` stores a `std::string_view` that points into a temporary `std::string`, and that temporary is destroyed before `firstLetter` later dereferences the view.

## Source

`UserProfile::displayName()` (line 8-10) returns a freshly constructed `std::string` by value - `first_ + " " + last_` is a temporary with no storage duration beyond the full expression that creates it. `ProfileCache::remember` (line 18-20) calls `profile.displayName()` and immediately constructs a `std::string_view` from that temporary's data to push into `names_`. The `std::string_view` never owns character storage; it only records the pointer/length of whatever it was given. Once the full expression in `remember` completes, the temporary `std::string` is destroyed and its buffer freed (or, for short strings, its stack-resident SSO buffer goes out of scope), leaving every `std::string_view` in `names_` pointing at freed/invalid memory. `ProfileCache::firstLetter` (line 22-24) later dereferences one of those dangling views via `names_[index][0]`, which reads freed memory - the use-after-free.

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

`displayName()` has no caller-owned string for a view to alias - it manufactures a new value on every call, so anything that needs to keep that value alive past the call must own a copy of the characters, not merely reference them. Changing `names_` from `std::vector<std::string_view>` to `std::vector<std::string>` makes `push_back` copy (or move) the returned string's contents into storage the vector itself owns, so the data stays valid for the vector's own lifetime regardless of how the caller produced it. `firstLetter` is unchanged: `std::string::operator[]` has the same signature and semantics as `std::string_view::operator[]` for a valid index, so no other code in the class needs to change. This is the general rule for `std::string_view` (and `std::span`, and any other non-owning view): it is only safe to store one when the referenced storage is known to outlive the view - a data member of an object that itself outlives the cache, a string literal, or a `std::string` held elsewhere with a longer lifetime - never the return value of a by-value-returning function.
