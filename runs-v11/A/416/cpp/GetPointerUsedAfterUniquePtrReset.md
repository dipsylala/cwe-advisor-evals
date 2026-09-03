## Verdict
Use after free confirmed. Line 31 extracts a raw pointer from `unique_ptr<Resource>` via `.get()`. Line 37 calls `.reset()` on the unique pointer, which destroys the Resource that the raw pointer references. Line 41 dereferences the dangling raw pointer, reading from freed memory.

## Source
`relayWithFallback()` stores a reference to a Resource object via a raw pointer (`rawHandle`) extracted from a `unique_ptr`. When `resourcePtr.reset()` deallocates that Resource, the raw pointer becomes invalid. Subsequent dereference at line 41 is a use-after-free.

## Fix
Capture the required metrics value before the `reset()` call:

```cpp
size_t relayWithFallback(const std::string& primaryEndpoint,
                          const std::string& fallbackEndpoint,
                          const std::string& payload) {
    std::unique_ptr<Resource> resourcePtr = std::make_unique<Resource>(primaryEndpoint);

    Resource* rawHandle = resourcePtr.get();
    rawHandle->send(payload);

    // Capture the metric before the Resource is destroyed
    size_t bytesSentOnPrimary = rawHandle->bytesSent();

    if (!fallbackEndpoint.empty()) {
        resourcePtr.reset(new Resource(fallbackEndpoint));
    }

    return bytesSentOnPrimary;
}
```

## Explanation
A raw pointer obtained via `unique_ptr::get()` remains valid only as long as the unique pointer still owns the object. Calling `unique_ptr::reset()` deallocates the owned object and invalidates all raw pointers to it. The fix captures the required value before deallocation, eliminating the window of vulnerability. The raw pointer is no longer dereferenced after the `reset()` call, and the function returns the correct metric from the original endpoint's send operation.
