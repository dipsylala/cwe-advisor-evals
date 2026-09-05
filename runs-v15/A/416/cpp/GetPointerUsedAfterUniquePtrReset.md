## Verdict

Use-after-free confirmed. At line 41, `rawHandle->bytesSent()` dereferences a pointer to an object destroyed by `resourcePtr.reset()` at line 37.

## Source

The vulnerability lies in the lifetime management of `rawHandle`:

1. Line 31: `Resource* rawHandle = resourcePtr.get()` – raw pointer obtained from unique_ptr
2. Line 37: `resourcePtr.reset(new Resource(fallbackEndpoint))` – destroys the original Resource that rawHandle points to
3. Line 41: `return rawHandle->bytesSent()` – accesses the destroyed object

## Fix

Capture the `bytesSent()` value before resetting the unique_ptr:

```cpp
size_t relayWithFallback(const std::string& primaryEndpoint,
                          const std::string& fallbackEndpoint,
                          const std::string& payload) {
    std::unique_ptr<Resource> resourcePtr = std::make_unique<Resource>(primaryEndpoint);

    // Grab a raw handle for use in this function's logging and metrics path.
    Resource* rawHandle = resourcePtr.get();
    rawHandle->send(payload);

    // Capture the value before the reset
    size_t bytesSentOnPrimary = rawHandle->bytesSent();

    if (!fallbackEndpoint.empty()) {
        // Switching targets destroys the Resource that rawHandle still points at;
        // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
        resourcePtr.reset(new Resource(fallbackEndpoint));
    }

    return bytesSentOnPrimary;
}
```

## Explanation

The issue occurs because `rawHandle` captures a raw pointer to the original Resource, but that object's lifetime is controlled by `resourcePtr`. When `resourcePtr.reset()` is called with a new object, the old Resource is destroyed while `rawHandle` still refers to it. The subsequent dereference at line 41 is undefined behavior.

The fix saves the metric value (`bytesSent()`) before the reset occurs. This eliminates the use-after-free because we no longer access the destroyed object; instead, we return the value captured while the object was still alive. The raw pointer `rawHandle` is never dereferenced after `reset()` is called, and the function correctly returns the byte count from the primary endpoint's send operation.
