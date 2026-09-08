## Verdict

Confirmed. `rawHandle` is a raw pointer obtained from `resourcePtr.get()` and used to call `send()` on the `Resource` owned by `resourcePtr`. When `fallbackEndpoint` is non-empty, `resourcePtr.reset(new Resource(fallbackEndpoint))` destroys the original `Resource` object that `rawHandle` still points at and makes `resourcePtr` own an unrelated, freshly-constructed `Resource`. The subsequent `rawHandle->bytesSent()` call therefore dereferences a dangling pointer into freed memory - a classic use-after-free. In practice this can return garbage, corrupt heap state, or crash, and the "new" byte count returned to the caller has nothing to do with the original send even when it doesn't crash.

## Source

- File: `GetPointerUsedAfterUniquePtrReset.cpp`
- Function: `relayWithFallback(const std::string& primaryEndpoint, const std::string& fallbackEndpoint, const std::string& payload)`
- Tainted/stale handle: `rawHandle` (line 31), obtained from `resourcePtr.get()` before `resourcePtr.reset(...)` (line 37) replaces (and frees) the object it owned.
- Sink: `rawHandle->bytesSent()` at line 41, called after the underlying object has already been freed by the `reset()` on line 37.

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

    // Capture the metric we need from the original Resource before it can be
    // destroyed. Reading through rawHandle after resourcePtr.reset() below
    // would dereference freed memory, since reset() destroys the object
    // rawHandle points at as soon as it installs the replacement.
    size_t bytesSentToPrimary = rawHandle->bytesSent();
    rawHandle = nullptr;

    if (!fallbackEndpoint.empty()) {
        // Switching targets destroys the Resource that rawHandle used to point
        // at; resourcePtr now owns a brand-new Resource for fallbackEndpoint.
        resourcePtr.reset(new Resource(fallbackEndpoint));
    }

    return bytesSentToPrimary;
}
```

## Explanation

The root cause is holding a raw, non-owning pointer (`rawHandle`) across a point where the owning `unique_ptr` can reassign or release its managed object. `unique_ptr::reset()` first destroys the currently-owned object and then takes ownership of the new pointer, so any raw pointer or reference obtained from the smart pointer before the `reset()` call becomes immediately dangling; using it afterward is undefined behavior regardless of whether it happens to "look like" it still works.

The fix removes the dependency on the raw handle surviving past the point of potential destruction: the one piece of data the function actually needs from the original `Resource` - the byte count from the primary send - is read through `rawHandle` immediately after `send()` and stored in a local variable (`bytesSentToPrimary`) while the pointer is still guaranteed valid. `rawHandle` is then cleared to `nullptr` so it cannot be accidentally reused later in the function (a defense-in-depth measure - if code is later added after the `reset()` that mistakenly touches `rawHandle`, it fails fast on a null-pointer dereference instead of silently reading freed memory). The `reset()` call and the final `return` no longer touch the freed `Resource` at all; the function returns the value captured before invalidation, which also fixes the latent logic bug of the original code returning a metric for the wrong (fallback) object's memory in the first place.

This pattern generalizes: whenever a raw pointer/reference is taken from a `unique_ptr` (or any owning smart pointer) and the smart pointer may later be reset, reassigned, or allowed to go out of scope, either (a) extract and store the specific data needed before the ownership change, as done here, or (b) re-fetch a fresh raw pointer via `get()` after the ownership change if the *new* object's state is what's actually needed. Never keep using a pointer captured from before the `reset()`/reassignment.
