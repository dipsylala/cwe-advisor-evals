## Verdict

Use-after-free confirmed. The lambda captures a raw pointer to a Session object that is destroyed via `session.reset()` before the callback is executed, leaving the captured pointer dangling.

## Source

Line 29-36 in QueuedSessionCallbackDangling.cpp:
```cpp
Session *raw = session.get();

queue.enqueue([raw]() {
    raw->touch();
});

session.reset();
```

The raw pointer `raw` is extracted from the owned `unique_ptr<Session>`, captured in a lambda that is queued for later execution, and then the underlying object is destroyed via `reset()`. When the queued callback runs, it dereferences a pointer to freed memory.

## Fix

Replace the function to capture a `shared_ptr` instead of a raw pointer, deferring destruction until all callbacks have run:

```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    // Convert ownership to shared_ptr so the callback can extend the lifetime
    std::shared_ptr<Session> shared_session = std::move(session);

    queue.enqueue([shared_session]() {
        shared_session->touch();
    });

    // No reset needed; destruction is deferred until the callback completes
}
```

## Explanation

The vulnerability occurs because the lambda captures a raw pointer to an object whose ownership and lifetime are managed elsewhere. By the time the queued callback executes, the unique_ptr has already destroyed the Session.

The fix converts the unique_ptr to a shared_ptr, which allows the lambda to hold a copy of the ownership. Each copy of the shared_ptr increments the reference count, ensuring the Session object is not destroyed until all callbacks that reference it have completed execution. This satisfies the C++ guidance principle: "a lambda capturing by reference, or capturing a raw `this`, outlives the frame it referred to when it is stored in a callback or queue; capture a `shared_ptr` (or `weak_ptr`) instead."

The `reset()` call is no longer needed because the shared_ptr handles destruction automatically when the last reference (including those in queued callbacks) is released.

## Behaviour changes

- **Lifetime extension**: The Session object now remains alive as long as any queued callback referencing it has not yet executed.
- **Resource cleanup**: Rather than being destroyed immediately at the end of `scheduleSessionTouch`, the Session is destroyed when the callback completes (assuming no other code holds a reference).
- **No error paths added**: The fix does not introduce error handling; `std::move` from unique_ptr to shared_ptr is well-defined and always succeeds.
