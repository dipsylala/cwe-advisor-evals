## Verdict
**CONFIRMED** — Use-after-free via raw pointer into unique_ptr that is reset.

## Source
At line 31, a raw pointer `rawHandle` is extracted from the `unique_ptr` and captures the address of the Resource object. At line 37, `resourcePtr.reset()` is called, which deallocates the original Resource that `rawHandle` still references. At line 41, `rawHandle->bytesSent()` dereferences freed memory.

## Fix
### File: GetPointerUsedAfterUniquePtrReset.cpp
```cpp
#include <memory>
#include <stdexcept>
#include <string>

// Represents a pooled connection handle that must be re-armed with fresh
// configuration whenever the caller wants to switch targets mid-request.
class Resource {
public:
    explicit Resource(std::string endpoint) : endpoint_(std::move(endpoint)), bytesSent_(0) {}

    void send(const std::string& payload) {
        bytesSent_ += payload.size();
    }

    const std::string& endpoint() const { return endpoint_; }
    size_t bytesSent() const { return bytesSent_; }

private:
    std::string endpoint_;
    size_t bytesSent_;
};

// Sends a request body to primaryEndpoint, then re-points the connection at
// fallbackEndpoint and reports how many bytes the original send transferred.
size_t relayWithFallback(const std::string& primaryEndpoint,
                          const std::string& fallbackEndpoint,
                          const std::string& payload) {
    std::unique_ptr<Resource> resourcePtr = std::make_unique<Resource>(primaryEndpoint);

    // Grab a raw handle for use in this function's logging and metrics path.
    Resource* rawHandle = resourcePtr.get();
    rawHandle->send(payload);

    // Capture the metrics before switching targets, as the reset will destroy
    // the original Resource that rawHandle points to.
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
The vulnerability occurs because `rawHandle` holds a raw pointer into memory managed by the `unique_ptr` `resourcePtr`. When `reset()` is called on the unique_ptr, it deallocates the original Resource object, invalidating the pointer. The subsequent dereference at line 41 is a use-after-free.

The fix captures the needed value (`bytesSent()`) from the original Resource before calling `reset()`. This ensures the value is extracted while the object is still valid, and the freed memory is never dereferenced afterward. The raw pointer `rawHandle` becomes dangling after the reset, but it is no longer used, which is safe.
