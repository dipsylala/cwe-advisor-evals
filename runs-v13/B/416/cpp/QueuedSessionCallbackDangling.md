## Verdict

Confirmed. The lambda captures a raw pointer to a `Session` object whose lifetime is controlled by a `unique_ptr`. The `unique_ptr` is reset (destroying the object) before the callback executes, leaving the captured raw pointer dangling when the queued callback eventually runs.

## Source

Line 29-36 in QueuedSessionCallbackDangling.cpp:

```cpp
Session *raw = session.get();

queue.enqueue([raw]() {
    raw->touch();  // Line 33: SINK - dereference of dangling pointer
});

session.reset();  // Destroys the object while callback still holds raw pointer
```

The flow:
1. `scheduleSessionTouch` receives a `unique_ptr<Session>` (sole owner)
2. A raw pointer is extracted and captured by value in the lambda
3. The `unique_ptr` is reset, destroying the object
4. The queued callback outlives the object and attempts to dereference the stale pointer

## Fix

Replace raw pointer capture with `shared_ptr` capture to extend object lifetime to match callback lifetime:

```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    // Move unique_ptr into shared_ptr to share ownership with callback
    std::shared_ptr<Session> shared = std::move(session);

    queue.enqueue([shared]() {
        shared->touch();
    });
    
    // No explicit reset needed; shared_ptr goes out of scope
    // but the callback holds a reference keeping object alive
}
```

## Explanation

The original code breaks the object's lifetime contract by extracting a raw pointer to an owned object and using it after releasing ownership. The fix converts the `unique_ptr` (exclusive ownership) to a `shared_ptr` (shared reference counting) so the lambda can capture a second owner of the object. The callback now holds a reference that keeps the object alive until it completes. When `shared` goes out of scope at the end of the function, the reference count is still non-zero (the callback holds one), so destruction is deferred. Only when the callback runs and the lambda is destroyed does the reference count drop to zero and the object get freed—but by then, all accesses have completed safely.

## Behaviour changes

- **Lifetime extension**: The `Session` object now lives until the callback completes execution, not just for the duration of the `scheduleSessionTouch` function.
- **Reference counting overhead**: Switching from `unique_ptr` (no overhead) to `shared_ptr` (atomic reference count management) adds negligible synchronization cost per ownership transition, but there is no reference counting on every access (only on capture and destruction).
- **Safety gain**: The callback no longer holds a dangling pointer; it holds a valid owner that guarantees the object will not be destroyed while in use. If the object is somehow destroyed through another path, the shared_ptr will catch that at the next access.

