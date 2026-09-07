## Verdict
The code contains a use-after-free vulnerability (CWE-416) at line 33. A raw pointer to a dynamically allocated Session object is captured in a lambda, but the unique_ptr that owns the Session is immediately reset, deleting the object. When the lambda is later executed from the queue, it dereferences a dangling pointer.

## Source
The vulnerability occurs in the `scheduleSessionTouch()` function:
- Line 29: A raw pointer is extracted from the unique_ptr: `Session *raw = session.get();`
- Line 31-34: This raw pointer is captured by value in a lambda: `[raw]()`
- Line 36: The unique_ptr is reset: `session.reset();` - this deletes the Session object while the lambda still holds a dangling pointer to it
- Line 33: When the queued lambda executes, `raw->touch();` accesses freed memory

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
    queue.enqueue([session = std::move(session)]() {
        session->touch();
    });
}
```

## Explanation
The fix transfers ownership of the Session object into the lambda via move capture: `[session = std::move(session)]()`. This ensures that:

1. The lambda now owns the Session via its captured unique_ptr
2. The Session object remains alive for as long as the lambda exists in the queue
3. When the lambda is executed, the Session is still valid
4. When the lambda is destroyed after execution, the unique_ptr's destructor properly deallocates the Session

This is the standard C++ idiom for managing object lifetime in delayed callbacks and eliminates the dangling pointer entirely. No raw pointers are used, and ownership semantics are clear and exception-safe.
