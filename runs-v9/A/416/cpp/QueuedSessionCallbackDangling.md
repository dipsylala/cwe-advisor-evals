## Verdict

Confirmed. `scheduleSessionTouch` captures a raw `Session*` obtained from the `unique_ptr` into a callback that is queued for later execution, then immediately calls `session.reset()`, which destroys the `Session` object. Any later invocation of the queued callback dereferences `raw`, which points to freed memory - a classic use-after-free (CWE-416).

## Source

`E:/Github/cwe-advisor/evals/cases/416/cpp/QueuedSessionCallbackDangling/QueuedSessionCallbackDangling.cpp`

- Line 29: `Session *raw = session.get();` extracts a non-owning raw pointer from the `unique_ptr<Session>`.
- Lines 31-34: the raw pointer is captured by value into a `std::function<void()>` lambda that is pushed onto `CallbackQueue`, deferring its execution to an unspecified later point.
- Line 36: `session.reset();` destroys the `Session` the raw pointer refers to, while a reference to it (via `raw`) is still held by the queued callback.
- Line 33 (the SAST-flagged sink): `raw->touch();` runs whenever the queue later invokes the callback, dereferencing the now-dangling pointer.

## Fix

Move ownership of the `Session` into the lambda itself instead of capturing a raw observer pointer, and drop the manual `reset()`:

```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    queue.enqueue([session = std::move(session)]() {
        session->touch();
    });
}
```

The lambda's init-capture (`session = std::move(session)`, C++14 generalized capture) takes ownership of the `unique_ptr<Session>` and stores it inside the `std::function` closure. The `Session` object now stays alive for exactly as long as the queued callback exists, and is only destroyed when the callback is popped/destroyed after running (or when the queue itself is destroyed). There is no longer a raw pointer anywhere in this function, and no explicit `reset()` that could race ahead of the callback's execution.

If `Session` needs to be shared with other code paths beyond this callback (e.g. something else also holds a reference to the same session), use `std::shared_ptr<Session>` instead: change the parameter to `std::shared_ptr<Session> session`, capture it by value (`[session]() { session->touch(); }`), and have callers construct the session as a `shared_ptr`. That keeps the object alive as long as any owner - including the queued callback - still references it, rather than relying on a single unique owner whose lifetime the enqueuing function controls incorrectly.

## Explanation

`std::unique_ptr` expresses single, exclusive ownership: calling `.get()` hands out a *non-owning* observer pointer that carries no lifetime guarantee whatsoever. The bug here is a lifetime mismatch between two independent things that were implicitly assumed to be synchronized: the lifetime of the `Session` object (controlled by `session`, a local `unique_ptr` in `scheduleSessionTouch`) and the lifetime of the callback that references it (controlled by `CallbackQueue`, which stores the callback until some later, unrelated point in time decides to invoke it).

Once `session.reset()` runs on line 36, the `Session` is destroyed and its memory may be reused. The queued lambda, however, still exists in `callbacks_` and still holds `raw`, which now points at freed (and potentially reallocated/reinitialized) memory. Any subsequent invocation of that callback - which by construction happens after `scheduleSessionTouch` has already returned - dereferences a dangling pointer on line 33, producing undefined behavior: a crash, corrupted state, or, in an adversarial setting, exploitable memory corruption.

The general remediation pattern for this class of bug is to make the object's lifetime and the callback's lifetime the same thing rather than two things a human has to keep synchronized by convention. Moving the owning `unique_ptr` into the lambda's capture achieves this directly: the `Session`'s destruction is now tied to the `std::function`'s destruction, which the `CallbackQueue` controls, so there is no window where the callback outlives the object it references. Where multiple independent owners are legitimately needed, `shared_ptr` (captured by value, so the closure holds its own reference and increments the use count) achieves the same guarantee without requiring a single designated owner.
