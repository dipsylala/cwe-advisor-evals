## Verdict

**Confirmed**: CWE-416 (Use After Free) — line 41 dereferences `rawHandle`, a raw alias to a Resource that was destroyed by `resourcePtr.reset()` at line 37.

## Source

Line 31 caches a raw pointer via `resourcePtr.get()`:
```cpp
Resource* rawHandle = resourcePtr.get();
```

Line 37 destroys the Resource it points to:
```cpp
resourcePtr.reset(new Resource(fallbackEndpoint));
```

Line 41 attempts to dereference the destroyed object:
```cpp
return rawHandle->bytesSent();
```

## Fix

Save the value before `reset()` invalidates the pointer:

```cpp
size_t relayWithFallback(const std::string& primaryEndpoint,
                          const std::string& fallbackEndpoint,
                          const std::string& payload) {
    std::unique_ptr<Resource> resourcePtr = std::make_unique<Resource>(primaryEndpoint);

    // Grab a raw handle for use in this function's logging and metrics path.
    Resource* rawHandle = resourcePtr.get();
    rawHandle->send(payload);

    // Save the value before reset() destroys the Resource.
    size_t bytesSent = rawHandle->bytesSent();

    if (!fallbackEndpoint.empty()) {
        // Switching targets destroys the Resource that rawHandle still points at;
        // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
        resourcePtr.reset(new Resource(fallbackEndpoint));
    }

    return bytesSent;
}
```

## Explanation

The vulnerability arises because `rawHandle` is a raw pointer obtained from `resourcePtr.get()`, which is an alias not tracked by the smart pointer. When `resourcePtr.reset()` is called, it destroys the original Resource, invalidating `rawHandle`. The subsequent dereference at line 41 reads from deallocated memory.

The fix captures the required value (`bytesSent`) before the reset occurs, so the return statement no longer depends on the dangling pointer. This follows the C++ principle that raw aliases obtained from `get()` must not outlive the scope in which the owner remains valid.

## Behaviour changes

The return value is unchanged: `bytesSent` is captured from the original Resource before replacement and returned afterward. The fallback Resource is still correctly instantiated. No functional behaviour of the caller changes; the function returns the same data via the same interface.
