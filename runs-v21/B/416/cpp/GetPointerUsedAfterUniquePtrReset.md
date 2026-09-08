## Verdict

Use-after-free confirmed. The raw pointer `rawHandle` obtained from `resourcePtr.get()` becomes stale when `resourcePtr.reset()` destroys the original Resource at line 37. The dereference at line 41 accesses memory that has been freed and returned to the allocator.

## Source

```
relayWithFallback() at line 31: raw pointer extracted from unique_ptr
  rawHandle = resourcePtr.get()
  
Line 37: unique_ptr reset destroys the object rawHandle refers to
  resourcePtr.reset(new Resource(fallbackEndpoint))
  
Line 41: stale pointer dereferenced (SINK)
  return rawHandle->bytesSent()
```

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

    // Capture the byte count before releasing the original resource.
    size_t originalBytesSent = rawHandle->bytesSent();

    if (!fallbackEndpoint.empty()) {
        // Switching targets destroys the Resource that rawHandle still points at;
        // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
        resourcePtr.reset(new Resource(fallbackEndpoint));
    }

    return originalBytesSent;
}
```

## Explanation

The fix captures the value of `bytesSent()` from the original Resource before the `resourcePtr.reset()` call at line 37. This moves the dereference of `rawHandle` to line 44 (before the reset), where the pointer is still valid. The return statement now uses the captured value `originalBytesSent` instead of dereferencing the stale `rawHandle` after reset.

This follows the C++ guidance principle: "make every reference an owner where the language allows it, so release is whatever happens last and no enumeration of aliases is required." By capturing the needed value before the owner releases its resource, we eliminate the window where a stale alias could be dereferenced.

## Behaviour changes

- The byte count is now read before the Resource is reset, ensuring the read reflects the original resource's state (which is the intended semantics of the function).
- No change to function signature, return type, or external behavior - the function still returns the byte count from the original send operation.
- The new local variable `originalBytesSent` holds the value temporarily, eliminating the dangerous aliasing pattern.

