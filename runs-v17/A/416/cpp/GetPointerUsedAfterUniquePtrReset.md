## Verdict
CONFIRMED - The raw pointer `rawHandle` is used after the `unique_ptr` it was extracted from is reset, destroying the managed Resource object.

## Source
The vulnerability occurs in the `relayWithFallback()` function. A raw pointer is extracted from a `unique_ptr` at line 31, then the `unique_ptr` is reset at line 37 (destroying the original Resource), and finally the dangling raw pointer is dereferenced at line 41.

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

    // Capture the value before resetting the unique_ptr.
    size_t result = rawHandle->bytesSent();

    if (!fallbackEndpoint.empty()) {
        // Switching targets destroys the Resource that rawHandle still points at;
        // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
        resourcePtr.reset(new Resource(fallbackEndpoint));
    }

    return result;
}
```

## Explanation
The vulnerability arises because `rawHandle` is a raw pointer extracted from the `unique_ptr` at line 31. When `resourcePtr.reset()` is called at line 37, it deallocates the original Resource object that `rawHandle` points to. The subsequent dereference of `rawHandle` at line 41 accesses freed memory.

The fix captures the needed value (`bytesSent()`) into a local variable `result` before the `unique_ptr` is reset, ensuring all data is read while the object is still alive. This preserves the function's logic while eliminating the use-after-free error.
