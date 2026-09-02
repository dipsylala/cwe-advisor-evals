## Verdict

**Confirmed use-after-free**: The `ProfileCache` stores `std::string_view` objects that refer to temporary strings destroyed after `remember()` returns. Subsequent accesses in `firstLetter()` dereference dangling views bound to deallocated memory.

## Source

**File**: StringViewCacheDangling.cpp  
**Line**: 23 (access in `firstLetter()`)  
**Root cause**: Line 27 declares `std::vector<std::string_view> names_`, and line 19 stores a view of a temporary returned by `displayName()`. The temporary is destroyed at the end of the full expression; the view outlives its referent.

## Fix

Change line 27 from:
```cpp
std::vector<std::string_view> names_;
```

to:
```cpp
std::vector<std::string> names_;
```

This makes `ProfileCache` the owner of the cached display names. When `remember()` pushes a temporary or a view into the vector, the vector constructs its own copy and takes ownership. The string remains valid for the lifetime of the vector entry, and line 23's access is safe.

## Explanation

The vulnerability arises because `std::string_view` is a non-owning view—it extends no ownership of the object it refers to. Storing a view of a temporary in a data member or container is a use-after-free: the temporary is destroyed, and any later access to the view reads deallocated memory.

The fix replaces the non-owning view with an owning `std::string`. The vector now holds the full string objects, not just views of them. Ownership is clear: `ProfileCache` owns the names, and they remain valid as long as they are in the vector. The access at line 23 is now safe because the string still exists and has not been reallocated.

## Behaviour changes

- **Memory ownership**: `ProfileCache` now stores complete strings, not views. Memory is allocated and deallocated with the vector entries.
- **Initialization cost**: Copying a string into the vector is more expensive than storing a view, but this cost is unavoidable when the source data does not outlive the cache.
- **API compatibility**: The public interface (`remember()`, `firstLetter()`) remains unchanged. The callers see no difference.
- **Dangling reference elimination**: No view can outlive its referent, because the vector owns the full string.
