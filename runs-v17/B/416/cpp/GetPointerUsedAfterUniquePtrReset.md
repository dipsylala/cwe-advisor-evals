## Verdict

The vulnerability is confirmed. A raw pointer obtained from `unique_ptr::get()` is dereferenced after the `unique_ptr` has been reset, destroying the underlying object.

## Source

The vulnerable pattern occurs in `relayWithFallback()`:
- Line 31: `rawHandle` is extracted via `resourcePtr.get()`
- Line 37: `resourcePtr.reset()` destroys the original Resource
- Line 41: `rawHandle->bytesSent()` dereferences a stale pointer to the destroyed object

## Fix

Capture the required value before the `unique_ptr` is reset. The fix preserves the original intent to record the bytes sent on the primary endpoint before switching to the fallback.

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

    // Capture the byte count before we potentially reset the pointer.
    // The unique_ptr may release the Resource object below, invalidating rawHandle.
    size_t bytesSentOnPrimary = rawHandle->bytesSent();

    if (!fallbackEndpoint.empty()) {
        // Switching targets destroys the Resource that rawHandle still points at;
        // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
        resourcePtr.reset(new Resource(fallbackEndpoint));
    }

    // Return the bytes sent on the primary endpoint, captured before reset.
    return bytesSentOnPrimary;
}
```

## Explanation

The root cause is accessing a raw pointer after the `unique_ptr` has been reset. Per CWE-416 C++ guidance: "Smart pointers guarantee only the accesses made *through* them: `get()` ... are all raw aliases the owner knows nothing about."

The fix captures the value (`bytesSent()`) while the object is still alive (before the `reset()` call), eliminating the use-after-free. The raw handle `rawHandle` is extracted and used for `send()` and the value capture, both of which occur before `reset()`. After the reset, only the captured value is used, never the stale pointer.

## Behaviour changes

- Before: The program dereferences a stale pointer to a destroyed Resource object, causing undefined behaviour (memory corruption, crash, or incorrect reads from reallocated memory).
- After: The program captures the required metric value before the Resource is destroyed, then safely returns it without any access through the stale pointer.
- Functional outcome: Identical - the function still returns the byte count sent on the primary endpoint. The fix only changes how that value is accessed: captured before destruction rather than accessed after.
