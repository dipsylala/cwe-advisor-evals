## Verdict

Confirmed. `scheduleSessionTouch` captures a raw `Session*` obtained from the `unique_ptr` into a callback that is queued for later, deferred execution, then immediately destroys the pointed-to `Session` via `session.reset()`. Whenever the queued callback is eventually invoked, `raw->touch()` dereferences a pointer to an object that has already been freed.

## Source

- `E:/Github/cwe-advisor/evals/cases/416/cpp/QueuedSessionCallbackDangling/QueuedSessionCallbackDangling.cpp:29` - `Session *raw = session.get();` extracts a non-owning raw pointer from the owning `unique_ptr<Session>` parameter.
- `E:/Github/cwe-advisor/evals/cases/416/cpp/QueuedSessionCallbackDangling/QueuedSessionCallbackDangling.cpp:31-34` - the raw pointer is captured by value into a `std::function<void()>` closure and enqueued for execution at an unspecified later time (`CallbackQueue::enqueue`).
- `E:/Github/cwe-advisor/evals/cases/416/cpp/QueuedSessionCallbackDangling/QueuedSessionCallbackDangling.cpp:36` - `session.reset()` runs right after enqueueing, deleting the `Session` while the queue still holds a callback that references it via `raw`.
- `E:/Github/cwe-advisor/evals/cases/416/cpp/QueuedSessionCallbackDangling/QueuedSessionCallbackDangling.cpp:33` (sink) - `raw->touch();` executes whenever the queued callback later runs, dereferencing the already-freed `Session`.

The lifetime of the `Session` (bound to the `unique_ptr` local, destroyed at `reset()`) is shorter than the lifetime of the closure that references it (bound to however long `CallbackQueue` holds and eventually invokes the callback), so every invocation of the callback after `reset()` is a use-after-free.

## Fix

### File: QueuedSessionCallbackDangling.cpp
```cpp
#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <utility>

class Session {
public:
    explicit Session(std::string id) : id_(std::move(id)) {}
    void touch();

private:
    std::string id_;
};

class CallbackQueue {
public:
    void enqueue(std::function<void()> callback)
    {
        callbacks_.push(std::move(callback));
    }

private:
    std::queue<std::function<void()>> callbacks_;
};

void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    std::shared_ptr<Session> shared = std::move(session);

    queue.enqueue([shared]() {
        shared->touch();
    });
}
```

## Explanation

The root cause is an ownership mismatch: the closure needs the `Session` to stay alive until it runs, but it only captured a raw observer pointer while the actual owner (`session`, a `unique_ptr`) was destroyed before the closure's execution time.

The fix converts the sole owning `unique_ptr<Session>` into a `std::shared_ptr<Session>` and captures that shared pointer *by value* in the lambda instead of a raw pointer. `std::function` requires its target to be copy-constructible, which `unique_ptr` is not, so `shared_ptr` is the correct move-out-and-share-ownership vehicle here (a `unique_ptr` cannot itself be captured by value into a `std::function`). Because the lambda now holds its own reference-counted handle to the `Session`, the object's lifetime is extended for as long as the callback exists in the queue: it is destroyed only when the last owner - either the original `shared` local (which goes out of scope harmlessly) or the queued callback itself - releases it. The dangling-pointer window is eliminated because there is no longer a raw pointer that outlives its owner; ownership itself now travels with the callback.

The explicit `session.reset()` call is removed: it is no longer needed (and would be incorrect to keep), since resetting the original `shared_ptr` local only drops one of potentially several owning references and does not affect the copy already captured inside the enqueued callback.
