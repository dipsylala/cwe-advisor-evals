## Verdict

The finding is confirmed. Line 33 dereferences a dangling raw pointer. The `Session` object is deleted at line 36 via `session.reset()`, but the lambda captured on line 31 holds a raw pointer that is invoked later, resulting in use-after-free.

## Source

```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    Session *raw = session.get();

    queue.enqueue([raw]() {
        raw->touch();  // Line 33: raw pointer to deleted object
    });

    session.reset();   // Line 36: deletes the Session
}
```

The problem: `raw` is a borrowed pointer extracted from `session`. The lambda captures `raw` by value. After `session.reset()` deletes the object, the lambda holds a dangling pointer. When the callback queue invokes this lambda, `raw->touch()` accesses freed memory.

## Fix

```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    auto session_ptr = std::make_shared<Session>(std::move(*session));

    queue.enqueue([session_ptr]() {
        session_ptr->touch();
    });
}
```

Alternatively, if you prefer to keep `unique_ptr` at the call site:

```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    auto session_ptr = std::shared_ptr<Session>(std::move(session));

    queue.enqueue([session_ptr]() {
        session_ptr->touch();
    });
}
```

## Explanation

The fix converts the ownership model for the queued callback. Instead of capturing a raw pointer that outlives its referent, the lambda captures a `std::shared_ptr<Session>`. The `shared_ptr` increments its reference count in the lambda's capture, ensuring the `Session` object remains alive as long as the lambda exists in the queue.

When the callback is invoked, the `shared_ptr` still holds a valid reference. When the lambda is destroyed (either invoked and discarded or the queue is cleared), the `shared_ptr` decrements the count, and the object is freed only when all references are gone.

This approach:
- Eliminates the dangling pointer by extending object lifetime to match callback lifetime.
- Avoids manual lifetime management of raw pointers.
- Is exception-safe if the `enqueue()` throws or if callbacks are moved between containers.
