## Verdict

Exploitable. The code passes a raw pointer obtained from a unique_ptr to a lambda that is enqueued in a callback queue, then immediately destroys the underlying object. The lambda's captured pointer becomes dangling when it is later executed.

## Source

Line 27-37: `scheduleSessionTouch()` function receives a `std::unique_ptr<Session> session` parameter. At line 29, a raw pointer is extracted via `session.get()`.

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
    auto shared_session = std::shared_ptr<Session>(std::move(session));

    queue.enqueue([shared_session]() {
        shared_session->touch();
    });
}
```

## Explanation

The fix converts the exclusive ownership model (unique_ptr) to a shared ownership model (shared_ptr). The original code extracted a raw pointer from the unique_ptr and captured it in a lambda destined for a callback queue, then destroyed the unique_ptr immediately. This left the lambda holding a dangling pointer. The fixed code moves the unique_ptr into a shared_ptr, then captures that shared_ptr in the lambda. The lambda now holds an ownership reference to the object through the shared_ptr. The object is not freed until all shared_ptr references are released, which includes the one held by the lambda. When the lambda eventually executes, the shared_ptr is still valid and the object is guaranteed to be alive. This follows the C++ CWE-416 guidance: use shared_ptr for callbacks that may outlive the object they reference, and capture the shared_ptr so the callback holds an ownership stake in the object's lifetime.

## Behaviour changes

None. The callback still calls `touch()` on the Session object when executed. The object's lifetime is extended to match the callback's needs, but the functional behavior of the code remains unchanged. The Session object now persists at least as long as the callback remains queued, which is the correct behavior for a deferred callback operation.
