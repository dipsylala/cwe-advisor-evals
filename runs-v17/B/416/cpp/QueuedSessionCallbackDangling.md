## Verdict

Exploitable. A raw pointer to a `Session` object is captured by value in a lambda closure that is enqueued for later execution. The `Session` is then destroyed via `reset()` before the lambda runs, resulting in a use-after-free when the callback executes `raw->touch()` on the freed memory.

## Source

Line 27: the `std::unique_ptr<Session> session` parameter, the exclusive owner of the `Session` object. Line 29 extracts a raw pointer from this owner via `get()`. Line 36 releases the owner with `reset()`, destroying the `Session`.

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

void scheduleSessionTouch(std::shared_ptr<Session> session, CallbackQueue &queue)
{
    queue.enqueue([session]() {
        session->touch();
    });
}
```

## Explanation

The fix converts the function parameter from `std::unique_ptr<Session>` to `std::shared_ptr<Session>`. This changes ownership semantics: instead of unique ownership that is released when the function exits, the `Session` object now uses shared ownership. The lambda captures the `shared_ptr` by value, making the lambda an additional owner. The object remains alive until all owners release it—the captured pointer in the lambda is released when the lambda is destroyed, not before. This prevents the use-after-free: when the callback later executes and calls `session->touch()`, the `Session` object is guaranteed to be alive because the lambda still holds an owning reference to it.

The fix eliminates the raw pointer extraction (`session.get()`) and the premature `reset()` call. The C++ guidance states: "A lambda capturing by reference, or capturing a raw `this`, outlives the frame it referred to when it is stored in a callback or queue; capture a `shared_ptr` (or `weak_ptr`) instead."

## Behaviour changes

- **Parameter type**: Changed from `std::unique_ptr<Session>` to `std::shared_ptr<Session>`. Callers must now pass a `shared_ptr` or convert the unique pointer. This is a breaking change to the function signature, but required to extend the Session lifetime to match the callback.
- **Raw pointer extraction removed**: Line 29 (`Session *raw = session.get();`) is deleted. The lambda no longer holds a dangling raw pointer.
- **Ownership release removed**: Line 36 (`session.reset();`) is deleted. The Session object is no longer explicitly released in this function; instead, it is released when the lambda is destroyed.
- **Lambda capture changed**: The lambda now captures `session` (the `shared_ptr`) by value instead of `raw` (the raw pointer). This gives the lambda an owning reference that keeps the object alive.
- **Session lifetime extended**: The Session object now persists until the enqueued callback is executed and destroyed, rather than being destroyed immediately after `scheduleSessionTouch()` returns.

