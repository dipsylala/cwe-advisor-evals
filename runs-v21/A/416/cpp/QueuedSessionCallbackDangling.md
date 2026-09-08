## Verdict
VULNERABLE - Confirmed CWE-416 (Use After Free) at line 33.

## Source
The vulnerability is in `scheduleSessionTouch()`. A raw pointer to a `Session` object is captured in a lambda callback. The ownership of the original `unique_ptr` is then surrendered via `session.reset()` before the callback executes, resulting in a dangling pointer.

## Fix
Convert the `unique_ptr<Session>` to a `shared_ptr<Session>` and capture the shared pointer in the lambda. This extends the Session object's lifetime to match the callback's lifetime, preventing use-after-free.

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
    // Convert to shared_ptr to share ownership with the callback.
    // This ensures the Session remains valid when the callback executes.
    std::shared_ptr<Session> sharedSession = std::move(session);

    queue.enqueue([sharedSession]() {
        sharedSession->touch();
    });
}
```

## Explanation
The root cause is capturing a raw pointer to an object whose lifetime is controlled by a `unique_ptr` that is then reset. The lambda holds only `raw`, which becomes a dangling pointer after `session.reset()`.

The fix converts the `unique_ptr` to a `shared_ptr` before storing it in the callback. When the lambda captures `sharedSession`, it acquires a reference to the shared pointer, incrementing its reference count. The `shared_ptr` semantics guarantee that the underlying `Session` object is not deleted until all references are released — including the one held by the captured lambda. This ensures that when the callback later calls `touch()`, the object is guaranteed to be valid.

This approach uses standard C++ reference counting semantics and requires no changes to the `CallbackQueue` interface or the calling code.
