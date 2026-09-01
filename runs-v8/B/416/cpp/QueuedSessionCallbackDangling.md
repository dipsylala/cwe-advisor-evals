## Verdict

Use-after-free confirmed. A raw pointer extracted from a `unique_ptr` is captured in a queued callback and dereferenced after the object is destroyed.

## Source

Line 29: `Session *raw = session.get();` extracts a raw pointer from the owned `unique_ptr<Session>`.

Line 31: The lambda `[raw]() { ... }` captures this raw pointer by value and is enqueued for asynchronous execution.

Line 36: `session.reset();` destroys the `Session` object while the queued lambda still holds a dangling pointer to it.

## Fix

Change the function to use `shared_ptr<Session>` and capture the shared pointer in the lambda:

```cpp
void scheduleSessionTouch(std::shared_ptr<Session> session, CallbackQueue &queue)
{
    queue.enqueue([session]() {
        session->touch();
    });
}
```

The `shared_ptr` is moved into the lambda's capture, extending the Session object's lifetime until the callback executes. The object is freed only after every owner (including the lambda) has released its reference.

## Explanation

The original code attempts to separate the lifetime of the Session object (owned by `unique_ptr`) from the lifetime of the callback (queued asynchronously). The raw pointer capture guarantees neither. By moving to `shared_ptr`, the Session object automatically stays alive as long as the queued callback holds a reference to it. Reference counting ensures the destructor runs only after both the caller and the callback have released ownership, eliminating the use-after-free window.

The lambda no longer captures `raw` or needs `session.get()`; it directly captures `session` (the `shared_ptr`), which is both safe and idiomatic.

## Behaviour changes

- Ownership semantics change from exclusive (`unique_ptr`) to shared (`shared_ptr`). The Session object is freed when the last owner releases its reference, not when the caller's `unique_ptr` is reset.
- The function no longer calls `session.reset()` explicitly; the `shared_ptr` captured in the lambda keeps the object alive until the callback executes.
- No change to the callback's contract or execution timing: `touch()` is still called asynchronously on the same Session instance.
