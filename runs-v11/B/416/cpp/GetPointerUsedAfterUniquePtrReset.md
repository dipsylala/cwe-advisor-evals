## Verdict

exploitable

## Source

Line 37: `resourcePtr.reset(new Resource(fallbackEndpoint))` destroys the Resource object that `rawHandle` still points to.

## Fix

**Vulnerable code (lines 34–41):**
```cpp
if (!fallbackEndpoint.empty()) {
    // Switching targets destroys the Resource that rawHandle still points at;
    // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
    resourcePtr.reset(new Resource(fallbackEndpoint));
}

// SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
return rawHandle->bytesSent();
```

**Fixed code:**
```cpp
// Capture the metric from the live object before it is released.
size_t bytesSent = rawHandle->bytesSent();

if (!fallbackEndpoint.empty()) {
    // Switching targets destroys the Resource that rawHandle still points at;
    // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
    resourcePtr.reset(new Resource(fallbackEndpoint));
}

return bytesSent;
```

## Explanation

The vulnerability arises because `rawHandle` is a raw pointer obtained from `resourcePtr.get()` on a `unique_ptr`. The `unique_ptr` owns the Resource's lifetime. When `reset()` is called, the original Resource is destroyed, but `rawHandle` still holds a pointer to the freed memory. Dereferencing `rawHandle` afterward is a use-after-free. The fix captures the required metric (`bytesSent()`) from the live object before `reset()` is called, eliminating the need to dereference the freed memory. This aligns with the C++ guidance principle that non-owning aliases like raw pointers must not outlive the owner.

## Behaviour changes

none — the function still returns the byte count from the original Resource on the primary endpoint, obtained at the same logical point in the workflow, but now safely before the Resource is destroyed rather than unsafely after.
