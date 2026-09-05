## Verdict

exploitable

## Source

Line 31: `Resource* rawHandle = resourcePtr.get();` creates a raw pointer alias from the unique_ptr.

## Sink

Line 41: `return rawHandle->bytesSent();` dereferences the dangling pointer after the object has been destroyed.

## Fix

**Vulnerable Code:**
```cpp
std::unique_ptr<Resource> resourcePtr = std::make_unique<Resource>(primaryEndpoint);

// Grab a raw handle for use in this function's logging and metrics path.
Resource* rawHandle = resourcePtr.get();
rawHandle->send(payload);

if (!fallbackEndpoint.empty()) {
    // Switching targets destroys the Resource that rawHandle still points at;
    // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
    resourcePtr.reset(new Resource(fallbackEndpoint));
}

// SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
return rawHandle->bytesSent();
```

**Fixed Code:**
```cpp
std::unique_ptr<Resource> resourcePtr = std::make_unique<Resource>(primaryEndpoint);

// Grab the raw handle and perform the initial send.
Resource* rawHandle = resourcePtr.get();
rawHandle->send(payload);

// Capture the result before the Resource is destroyed.
size_t sentBytes = rawHandle->bytesSent();

if (!fallbackEndpoint.empty()) {
    // Switching targets destroys the Resource that rawHandle still points at;
    // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
    resourcePtr.reset(new Resource(fallbackEndpoint));
}

// Return the captured value, not the dangling pointer.
return sentBytes;
```

## Explanation

The vulnerability arises because `rawHandle` is a raw pointer obtained from `resourcePtr.get()`, which is merely an alias—it does not extend the object's lifetime. When `resourcePtr.reset()` is called on line 37, the original `Resource` is destroyed, but `rawHandle` still holds the address of the freed memory. Dereferencing it on line 41 reads from that freed location, which is a use-after-free.

The fix captures the required value (`sentBytes`) before the object is destroyed, eliminating the alias and the stale dereference. This ensures the function returns the correct byte count from the original resource, whether or not the fallback endpoint was activated.

## Behaviour changes

The captured value is stored in a local variable `size_t sentBytes` before the reset, and returned at the end instead of dereferencing the dangling pointer. This preserves the original function's return value and semantics—the caller receives the same result—but closes the use-after-free by ensuring no dereference occurs after the object is released. No other arguments, return values, or control flow are altered.
