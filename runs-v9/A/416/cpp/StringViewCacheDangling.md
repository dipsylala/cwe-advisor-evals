## Verdict

Confirmed. `ProfileCache::names_` stores `std::string_view` elements that are bound to temporary `std::string` objects, and those temporaries are destroyed before the views are ever read, so `firstLetter()` dereferences freed memory.

## Source

`UserProfile::displayName()` (line 8-10) builds and returns a brand-new `std::string` by value on every call (`first_ + " " + last_` is a fresh temporary, not a reference into `first_`/`last_`).

## Fix

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

The only change is the element type of `names_`: `std::vector<std::string_view>` becomes `std::vector<std::string>`.

## Explanation

`remember()` calls `profile.displayName()`, which constructs and returns a temporary `std::string` by value. That temporary is used only to initialize the `std::string_view` pushed into `names_`. A `string_view` never copies or owns character data - it just stores a pointer and a length into whatever buffer it was given. The temporary `std::string` is destroyed at the end of the full expression (i.e., right after `push_back` returns), which frees its internal buffer. From that point on, every `string_view` in `names_` points at deallocated memory.

`firstLetter()` then evaluates `names_[index][0]`, dereferencing the dangling pointer stored in the view. This is a classic use-after-free: the read happens on memory the allocator may have already reused, so the call can return garbage, crash, or (with ASan/hardened allocators) reliably abort - and in a long-running cache it can also read another object's data, since nothing prevents an unrelated allocation from landing in the freed slot.

The fix stores the cache entries by value as `std::string` instead of viewing them. Each `std::string` in the vector owns its own heap-allocated (or SSO-inline) buffer, so the data returned by `displayName()` is copied/moved into cache-owned storage that lives exactly as long as the `ProfileCache` entry does. `firstLetter()` then indexes into memory the cache itself controls, eliminating the dangling reference. `std::string_view` remains safe only when it borrows from storage whose lifetime is guaranteed to outlive the view - here that guarantee does not hold, because the data source is a per-call temporary, not a member of `profile` itself. If avoiding the copy were a hard requirement, the alternative would be to change `remember()`'s contract to take and store the caller-owned `std::string` (or a smart pointer to one) rather than a view derived from a temporary, but that reshapes the API; storing by value is the minimal, correct fix here.
