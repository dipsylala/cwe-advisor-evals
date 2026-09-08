## Verdict

Exploitable. `ProfileCache::remember` stores `profile.displayName()` into `std::vector<std::string_view> names_`. `displayName()` returns a `std::string` by value; that returned object is a temporary bound only for the duration of the full expression `names_.push_back(profile.displayName())`. The `std::string_view` constructed from it captures a pointer into that temporary's buffer, and the temporary is destroyed once the statement completes - before `remember()` even returns. Any later call to `firstLetter(index)` (line 23, `names_[index][0]`) dereferences a pointer into freed memory: a classic use-after-free, since a `string_view` never extends the lifetime of what it views.

## Source

`UserProfile::displayName()` - returns `first_ + " " + last_` by value, a freshly constructed temporary `std::string` with no lifetime tie to the caller.

## Fix

### File: StringViewCacheDangling.cpp

```cpp
#include <cstddef>
#include <string>
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

`names_` is changed from `std::vector<std::string_view>` to `std::vector<std::string>`, so the cache owns each name instead of merely viewing one. `remember()` is unchanged in source but now behaves differently at the ABI level: `push_back` moves/copies the temporary `std::string` returned by `displayName()` into a vector element it owns, rather than binding a non-owning view to a value that is about to be destroyed. `firstLetter()` is untouched - `std::string::operator[]` has the same signature and semantics as the `string_view` version it replaces - so the dangling-pointer read is eliminated by giving the cache a real owner for the data it needs to keep, per the CWE-416 C++ guidance's rule that a view belongs only in a parameter or a short-lived local, and that a container caching data across calls should hold a value type (`std::vector<std::string>`) rather than a view into something else's temporary.

The now-unused `<string_view>` include was removed since nothing in the file uses `std::string_view` after the fix.

## Behaviour changes

- `ProfileCache` now owns a copy of each remembered name (heap-allocated small-string storage per entry, or SSO-inline for short names) instead of holding a 16-byte view; memory footprint per cached name increases accordingly. This is the change that fixes the bug - the prior "cheap view" was never valid at any point after `remember()` returned, so there is no working behaviour being traded away.
- No change to `remember()`'s or `firstLetter()`'s signature, return type, or observable results for correctly-freed inputs - the fix corrects previously-undefined behaviour rather than altering defined behaviour.
- Removed the unused `#include <string_view>`, a direct consequence of removing the only `string_view` usage in the file.

## Verification

No C++ compiler (`g++`, `clang++`, `cl`) was reachable in this environment, so the fix was checked by manual read-through rather than compiled: `std::vector<std::string>`'s `push_back(std::string)` accepts the `std::string` prvalue returned by `displayName()` via move construction (a standard-library API, `<vector>`/`<string>`, both already included); `operator[]` on `std::string` returns `char&`, matching `firstLetter`'s `char` return type exactly as the `std::string_view::operator[]` it replaces did. No new symbols, includes, or third-party names were introduced beyond the standard library types already in use elsewhere in the file.
