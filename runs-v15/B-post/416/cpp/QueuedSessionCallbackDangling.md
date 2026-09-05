## Verdict

Confirmed use-after-free. The lambda captures a raw pointer to a Session object that is destroyed immediately after being queued, leaving the callback with a dangling pointer.

## Source

The Session object in `scheduleSessionTouch()` is held by `std::unique_ptr<Session> session` (line 27). A raw pointer is extracted via `session.get()` (line 29) and captured by value in a lambda (line 31). The object is then destroyed via `session.reset()` (line 36), while the queued lambda still holds the dangling pointer.

## Fix

Convert the function to accept `std::shared_ptr<Session>` and capture the shared pointer in the lambda. This gives the callback shared ownership of the Session object, keeping it alive for as long as the callback exists.

**Vulnerable code:**
```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    Session *raw = session.get();

    queue.enqueue([raw]() {
        // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
        raw->touch();
    });

    session.reset();
}
```

**Fixed code:**
```cpp
void scheduleSessionTouch(std::shared_ptr<Session> session, CallbackQueue &queue)
{
    queue.enqueue([session]() {
        session->touch();
    });
}
```

## Explanation

The original code passes a `unique_ptr`, extracts a raw pointer for the lambda, and immediately destroys the Session object. When the lambda eventually executes, it dereferences a pointer to freed memory. The fix converts to `shared_ptr` and captures it directly in the lambda. The shared pointer in the lambda's capture holds a reference to the Session object, preventing its destruction until the lambda completes execution. The object is now owned by both the caller's initial shared_ptr (before being passed) and the lambda's captured copy, ensuring it remains valid when needed. The explicit `reset()` call is no longer needed since the object's lifetime is now tied to the lambda's lifecycle via reference counting.

## Behaviour changes

The Session object's lifetime is extended from the caller's scope to the point when the queued lambda finishes executing. If the callback queue retains callbacks for an indefinite time, the Session object persists accordingly. This is the intended and safe behaviour—keeping the object alive as long as any component still needs to reference it, which is the core defence against use-after-free.
