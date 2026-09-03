## Verdict

The finding is confirmed. The code captures a raw pointer to a dynamically allocated Session object and then explicitly deletes it via `session.reset()` before the callback that uses the pointer ever executes. When the queued callback runs, it dereferences a dangling pointer.

## Source

```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    Session *raw = session.get();

    queue.enqueue([raw]() {
        // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
        raw->touch();
    });

    session.reset();  // Deletes the Session object while raw still holds its address
}
```

## Fix

```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    queue.enqueue([session = std::move(session)]() {
        session->touch();
    });
}
```

## Explanation

The fix transfers ownership of the Session object into the lambda's capture list using move semantics. The lambda now holds the only reference to the `unique_ptr`, and the Session remains alive for the entire lifetime of the callback. When the callback executes, the pointer is valid. When the callback completes and is destroyed, the `unique_ptr` destructor automatically cleans up the Session object.

This eliminates the manual `session.reset()` call and the raw pointer capture. The unique_ptr remains the sole owner of the lifetime, but its ownership transfers to the place where it is actually used—the lambda—rather than being deleted early while a reference to its data remains.
