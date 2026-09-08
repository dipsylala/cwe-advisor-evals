## Verdict

exploitable

## Source

Widget object created at line 51 in handleRequest() as a stack-allocated local variable.

## Sink

Lambda dereference at line 32: `queue.post([this]() { this->onTimerFired(); });`. The raw `this` pointer is captured and stored in the task queue, then dereferenced after the Widget object has been destroyed.

## Fix

### File: LambdaCapturedThisQueuedAsync.cpp

```cpp
#include <functional>
#include <memory>
#include <vector>

// Minimal deferred task queue standing in for a real async executor, such
// as asio::io_context::post() or a thread pool's submit().
class TaskQueue {
public:
    void post(std::function<void()> task) {
        tasks_.push_back(std::move(task));
    }

    void runPending() {
        for (auto& task : tasks_) {
            task();
        }
        tasks_.clear();
    }

private:
    std::vector<std::function<void()>> tasks_;
};

class Widget : public std::enable_shared_from_this<Widget> {
public:
    explicit Widget(int id) : id_(id) {}

    // Arms a deferred callback that fires once the owning event loop gets
    // around to draining the queue, which may be long after this call
    // returns.
    void startTimer(TaskQueue& queue) {
        queue.post([self = shared_from_this()]() { self->onTimerFired(); });
    }

    void onTimerFired() {
        lastFiredId_ = id_;
    }

    int lastFiredId() const { return lastFiredId_; }

private:
    int id_;
    int lastFiredId_ = 0;
};

// Simulates a request handler that creates a short-lived Widget, arms its
// timer against the shared queue, and returns. The Widget is destroyed at
// the end of this function, well before runPending() ever drains the
// queue, so the queued lambda's captured `this` is left dangling.
void handleRequest(TaskQueue& queue) {
    auto widget = std::make_shared<Widget>(42);
    widget->startTimer(queue);
} // widget shared_ptr released here, but Widget stays alive because
  // the lambda in the queue holds a shared_ptr reference to it

void runEventLoop(TaskQueue& queue) {
    handleRequest(queue);
    // The lambda captured earlier now runs, dereferencing a safe
    // shared_ptr to the Widget object, which is still alive.
    queue.runPending();
}

int main() {
    TaskQueue queue;
    runEventLoop(queue);
    return 0;
}
```

## Explanation

The fix replaces the raw `this` pointer capture with a `shared_ptr`-based ownership model. Widget now derives from `std::enable_shared_from_this<Widget>`, allowing it to produce a `shared_ptr` to itself. The lambda now captures `[self = shared_from_this()]`, which copies the shared_ptr into the lambda's closure. In `handleRequest`, the Widget is created via `std::make_shared` instead of as a stack variable, so it is managed by a shared_ptr. When `handleRequest` returns, the local `widget` shared_ptr goes out of scope, but the reference count remains > 0 because the queued lambda holds a shared_ptr reference. The Widget object is not destroyed until the lambda executes and goes out of scope. When the lambda runs and calls `self->onTimerFired()`, it dereferences a live object, eliminating the use-after-free.

## Behaviour changes

The Widget object is now heap-allocated and managed by shared_ptr instead of stack-allocated. This changes the allocation strategy but does not alter the observable behavior of the program—the widget still fires its timer callback and records the ID correctly, and the object is destroyed at the same logical point (after the callback runs).

## Verification

**Manual semantic review** of the fixed code:
- `#include <memory>` added for `std::shared_ptr` and `std::enable_shared_from_this`
- `Widget` class now publicly derives from `std::enable_shared_from_this<Widget>` (standard pattern, available in C++11)
- Lambda capture `[self = shared_from_this()]` uses initializer-capture form (C++14+) to copy the shared_ptr into the lambda's closure
- `std::make_shared<Widget>(42)` in `handleRequest` creates the Widget as a managed heap object
- Call `self->onTimerFired()` correctly accesses the method through the captured shared_ptr
- All required headers are present and all APIs are standard library functions
- No undefined behavior: the Widget object is guaranteed to outlive the lambda's execution because the lambda holds a shared_ptr reference to it

The fix applies the standard C++ pattern recommended in the CWE-416 guidance for callbacks that outlive their capture scope: deriving from `enable_shared_from_this` and capturing the result of `shared_from_this()` instead of a raw `this` pointer.

