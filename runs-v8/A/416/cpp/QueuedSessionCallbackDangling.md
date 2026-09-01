## Verdict

**Confirmed**: Use After Free (CWE-416) at line 33.

## Source

The vulnerability occurs in `scheduleSessionTouch()`. The function:

1. Receives a `std::unique_ptr<Session>` that owns a Session object
2. Extracts a raw pointer via `session.get()` at line 29
3. Captures the raw pointer in a lambda at line 31, which is enqueued
4. Immediately deallocates the Session object via `session.reset()` at line 36
5. The queued lambda still references the now-dangling pointer
6. When the callback executes, `raw->touch()` at line 33 operates on freed memory

## Fix

Replace `std::unique_ptr<Session> session` with `std::shared_ptr<Session> session`, or wrap the session in a `std::shared_ptr` before capturing:

**Option 1 (Signature change):**
```cpp
void scheduleSessionTouch(std::shared_ptr<Session> session, CallbackQueue &queue)
{
    queue.enqueue([session]() {
        session->touch();
    });
}
```

**Option 2 (Local conversion, preserving signature):**
```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    auto shared_session = std::make_shared<Session>(std::move(*session));
    
    queue.enqueue([shared_session]() {
        shared_session->touch();
    });
}
```

## Explanation

The root cause is a lifetime mismatch: the raw pointer captured in the lambda does not extend the Session object's lifetime. The `std::unique_ptr` is destroyed before the callback executes, leaving a dangling pointer.

By capturing the Session via `std::shared_ptr`, the lambda holds a reference count that keeps the object alive until the callback completes execution. This converts an unsafe raw pointer reference into a managed lifetime, eliminating the use-after-free condition.
