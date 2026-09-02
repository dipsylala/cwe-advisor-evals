## Verdict

exploitable (confidence: high)

## Source

`UserProfile::displayName()` (line 8-10) constructs and returns a `std::string` **by value** (`first_ + " " + last_`), which is a temporary at the call site.

## Fix

Vulnerable code (`StringViewCacheDangling.cpp`, lines 16-28):

```cpp
class ProfileCache {
public:
    void remember(const UserProfile& profile) {
        names_.push_back(profile.displayName()); // VULNERABLE: string_view binds to a temporary std::string
    }

    char firstLetter(std::size_t index) const {
        return names_[index][0]; // reads through a dangling string_view
    }

private:
    std::vector<std::string_view> names_;
};
```

Fixed code:

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

`remember()` calls `profile.displayName()`, which returns a freshly constructed `std::string` by value - a temporary. The original code stored that temporary as a `std::string_view` in `names_`. A `string_view` never extends the lifetime of what it views, so the temporary `std::string` is destroyed at the end of the full expression (the `push_back` statement), leaving `names_` holding a view into freed/reused memory. `firstLetter()` then dereferences that dangling view (`names_[index][0]`), which is a use-after-free: it may read stale bytes, corrupted bytes, or crash, and the fault is silent at the call site that caused it. The fix changes `names_` from `std::vector<std::string_view>` to `std::vector<std::string>`, so `push_back` copies (or move-constructs) the returned string into a container-owned `std::string` with its own storage. `names_` becomes the sole owner of each cached name, and `firstLetter()` reads from that owned storage instead of a view of a destroyed temporary, eliminating the dangling reference.

## Behaviour changes

- `names_`'s element type changes from `std::string_view` to `std::string`, and each `remember()` call now owns a copy of the display name (a small additional allocation/copy per call) instead of a non-owning view - required to give the cached data a lifetime independent of the temporary returned by `displayName()`.
- `remember()` and `firstLetter()` are otherwise unchanged: same signatures, same return values, same indexing behaviour on valid indices.
- Out-of-range `index` handling in `firstLetter()` is unchanged (still unchecked `operator[]`); this is a pre-existing property of the sink unrelated to the use-after-free and was left as-is.
