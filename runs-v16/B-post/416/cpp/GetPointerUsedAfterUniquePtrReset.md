## Verdict
exploitable

## Source
Line 31: `Resource* rawHandle = resourcePtr.get();` - retrieves a raw, non-owning pointer to the Resource owned by `resourcePtr`

## Fix

**Vulnerable code:**
```cpp
    // Grab a raw handle for use in this function's logging and metrics path.
    Resource* rawHandle = resourcePtr.get();
    rawHandle->send(payload);

    if (!fallbackEndpoint.empty()) {
        // Switching targets destroys the Resource that rawHandle still points at;
        // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
        resourcePtr.reset(new Resource(fallbackEndpoint));
    }

    // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
    return rawHandle->bytesSent();  // BUG: rawHandle is stale after reset()
```

**Fixed code:**
```cpp
    // Grab a raw handle for use in this function's logging and metrics path.
    Resource* rawHandle = resourcePtr.get();
    rawHandle->send(payload);

    // Record the bytes sent before the original resource may be destroyed
    size_t bytes_sent = rawHandle->bytesSent();

    if (!fallbackEndpoint.empty()) {
        // Switching targets destroys the Resource that rawHandle still points at;
        // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
        resourcePtr.reset(new Resource(fallbackEndpoint));
    }

    return bytes_sent;
```

## Explanation
The vulnerability arises from caching a raw pointer alias to an object owned by a `unique_ptr`, then dereferencing that stale pointer after the `unique_ptr` releases the object. Line 31 calls `resourcePtr.get()` to obtain a raw pointer; this pointer is a non-owning alias the `unique_ptr` knows nothing about. When `resourcePtr.reset()` is called at line 37, it destroys the old Resource and replaces it with a new one, leaving `rawHandle` pointing to freed memory. The use at line 41 accesses that freed memory. The fix captures the required value (`bytes_sent`) before the original Resource is released, then returns the captured value after the reset, ensuring no access to deallocated memory occurs.

## Behaviour changes
The function now captures `bytesSent()` before the potential reset. The captured value is stored in a new local variable `bytes_sent` and returned instead of dereferencing `rawHandle` after the reset. This changes the timing of the `bytesSent()` call from after the reset to before it, but preserves the function's contract: it still returns the number of bytes sent to the primary endpoint, which is the value `bytesSent()` held before the reset occurred.
