## Verdict

exploitable

- cwe_id: CWE-416 (Use After Free)
- location: `GetPointerUsedAfterUniquePtrReset.cpp`, line 41 (sink); the freeing operation is line 37
- confidence: high

## Source

`resourcePtr.get()` at line 31 hands out a raw, non-owning alias (`rawHandle`) to the `Resource` object owned by `std::unique_ptr<Resource> resourcePtr`. `rawHandle` carries no lifetime guarantee of its own - it is only valid for as long as `resourcePtr` continues to own that same object.

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

    // Capture the metric while rawHandle is still guaranteed valid. Reading
    // it after the possible reset() below would dereference a Resource that
    // resourcePtr has already destroyed.
    size_t bytesSentToPrimary = rawHandle->bytesSent();

    if (!fallbackEndpoint.empty()) {
        // Switching targets destroys the Resource that rawHandle pointed at;
        // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
        // rawHandle is not read again after this point.
        resourcePtr.reset(new Resource(fallbackEndpoint));
    }

    return bytesSentToPrimary;
}
```

## Explanation

The unsafe pattern is the second half described in the CWE-416/C++ guidance: ownership itself is correct (`resourcePtr` is the sole owner of each `Resource` it holds), but `rawHandle` is a raw, non-owning alias whose lifetime is not bounded by the owner's. `resourcePtr.reset(new Resource(fallbackEndpoint))` at line 37 destroys the primary `Resource` and makes `resourcePtr` own a new one; `rawHandle` still points at the destroyed object. Line 41's `rawHandle->bytesSent()` then dereferences that dangling pointer - freeing does not unmap the memory, so this read can silently return stale or reused-memory data rather than crashing, which is exactly the two symptom classes (corruption or no visible symptom at the defect site) the guidance calls out.

The fix moves the read the function actually needs - the byte count for the send that happened through the primary `Resource` - to occur immediately after `rawHandle->send(payload)`, before any code path that can destroy the object `rawHandle` refers to. `rawHandle` is not dereferenced anywhere after the `reset()` call. This satisfies the sink's existing contract exactly: `bytesSent()` is a pure `const` accessor with no side effects and no failure mode, and the function's documented purpose ("reports how many bytes the original send transferred") is preserved - the returned value is still the primary send's byte count, just obtained from well-defined memory instead of from a freed object.

## Behaviour changes

- The point at which `bytesSent()` is read moved from after the conditional `reset()` (line 41, dangling) to immediately after `rawHandle->send(payload)` (before line 34's `if`), storing the result in a new local, `bytesSentToPrimary`. Reason: this is the only way to read the primary `Resource`'s byte count without dereferencing it after it may have been destroyed. It does not change what value the function is documented to return - `bytesSent_` is only ever incremented once, by the `send(payload)` call two lines above, so the value read early is identical to the value the (undefined) late read was attempting to obtain; the original code's read was simply unsafe, not differently-valued.
- No other arguments, return type, control flow, or discarded output changed. `rawHandle` is left in place (still assigned from `resourcePtr.get()`) and unused after the `reset()`, rather than nulled, since it is never dereferenced again; nulling it was not necessary to close this specific path and was omitted to keep the diff minimal.

## Verification

No C++ compiler (`g++`, `clang++`, `cl`) was reachable in this environment, so the fix was checked by hand instead of compiled:
- `bytesSentToPrimary` is a newly declared `size_t` local, initialized once from `rawHandle->bytesSent()` (a method that exists on `Resource` in the original file, unchanged) and returned unchanged at the end of the function - no type mismatch with the function's `size_t` return type.
- `rawHandle`, `resourcePtr`, `send`, `bytesSent`, `Resource`, `reset`, and `make_unique` are all identifiers already present in the original file or in `<memory>`/`<string>`, already included; no new headers, symbols, or dependencies were introduced.
- Traced every use of `rawHandle`: it is declared once (line "Resource* rawHandle = resourcePtr.get();"), used at `send(payload)` and `bytesSent()` immediately after, then never referenced again - so no use-after-free path remains, including inside the `if` block and after it.
