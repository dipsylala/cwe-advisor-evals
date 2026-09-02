## Verdict

Exploitable. Confidence: high.

## Source

`scheduleSessionTouch` takes ownership of a `Session` via `std::unique_ptr<Session> session` (line 27). It extracts a raw observer pointer with `Session *raw = session.get()` (line 29) and captures `raw` by value into a lambda that is queued on `CallbackQueue` (lines 31-34) for deferred, later execution. Before that callback can run, `session.reset()` (line 36) destroys the `Session` object. The queue only stores the `std::function<void()>` - it holds no reference that keeps the `Session` alive - so by the time the queued callback runs, `raw` is a dangling pointer to freed memory.

Sink: `raw->touch()` at line 33, executed whenever `CallbackQueue`'s stored callback is later invoked, which is always after `scheduleSessionTouch` has returned and the object has been released.

## Fix

Vulnerable code:

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

Fixed code:

```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    std::shared_ptr<Session> shared = std::move(session);

    queue.enqueue([shared]() {
        shared->touch();
    });
}
```

## Explanation

The callback needs the `Session` to still be alive whenever the queue eventually runs it, so the fix converts the incoming `unique_ptr` into a `shared_ptr` and captures that `shared_ptr` by value in the lambda, per the CWE-416 C++ guidance's rule for a callback that outlives the frame it was created in: give it real ownership rather than a raw alias. The lambda's captured copy keeps the `Session` reference-counted and alive for as long as the callback itself is queued, so `touch()` always runs against a live object no matter when the queue drains it. The explicit `session.reset()` is removed because it is no longer needed - and was in fact the immediate cause of the dangling pointer - since ownership has already moved out of the local `unique_ptr` into the shared, reference-counted owner captured by the callback.

## Behaviour changes

- `scheduleSessionTouch` no longer destroys the `Session` before returning; its lifetime now extends until the queued callback has run (and any other `shared_ptr` copies, if added elsewhere, have released it). This is the change required to make the sink safe: the callback's entire purpose is to touch the session later, which is only possible if the object still exists at that point.
- The object is now managed by `std::shared_ptr` instead of `std::unique_ptr` for the remainder of its lifetime. `CallbackQueue` and `Session` themselves are unchanged; the queue still stores only `std::function<void()>` values, and `touch()` is invoked with the same signature and no altered arguments or return-value handling.
