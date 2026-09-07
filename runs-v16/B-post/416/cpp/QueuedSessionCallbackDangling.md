## Verdict

Exploitable

## Source

Session object ownership passed to `scheduleSessionTouch()` as `unique_ptr<Session> session` (parameter, line 27). The object is freed at line 36 while a callback holding a raw pointer to it remains queued.

## Sink

Dereference of raw pointer `raw` via `raw->touch()` at line 33, inside a lambda captured in a callback queue. Execution occurs after the underlying Session has been destroyed.

## Fix

**Vulnerable code:**
```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    Session *raw = session.get();

    queue.enqueue([raw]() {
        // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
        raw->touch();  // Use-after-free: raw pointer outlives the object it points to
    });

    session.reset();  // Object destroyed here, raw pointer now dangling
}
```

**Fixed code:**
```cpp
void scheduleSessionTouch(std::shared_ptr<Session> session, CallbackQueue &queue)
{
    queue.enqueue([session]() {
        session->touch();  // session is now an owner; object stays alive while callback is queued
    });
}
```

## Explanation

The vulnerability occurs because a raw pointer extracted from a `unique_ptr` is captured in a lambda that outlives the unique_ptr's lifetime. When `session.reset()` destroys the object, the lambda's captured `raw` pointer becomes a dangling reference. Later execution of the callback dereferences freed memory.

The fix replaces `unique_ptr<Session>` with `shared_ptr<Session>` and captures the shared_ptr by value in the lambda. This makes the lambda an owner of the Session object, extending its lifetime until the callback completes. The `shared_ptr` reference count ensures the object is not destroyed while any owner (including the lambda) holds it. The explicit `session.reset()` is no longer needed; the object is released automatically when the last owner (the callback) finishes.

## Behaviour changes

- Function parameter type changes from `unique_ptr<Session>` to `shared_ptr<Session>`. Callers must adapt: code passing a `unique_ptr` can convert via `std::move()` to a temporary `shared_ptr`, or the caller should construct the Session directly into a `shared_ptr`. This is a caller-side change, not a change in the callee's logic.
- The `session.reset()` call is removed, relying on automatic reference-counting cleanup instead of explicit release. This preserves the semantics: the object is still released after use, but the timing shifts from the function return to the callback's completion.
- The callback retains its ability to call `session->touch()` unchanged; the access pattern to the member function is identical.
