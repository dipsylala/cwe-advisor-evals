## Verdict
Exploitable

## Source
The `Widget` object created as a stack-local variable in `handleRequest()` at line 51.

## Fix
The vulnerability occurs because the lambda at line 32 captures a raw `this` pointer that becomes dangling after `Widget` is destroyed. The fix applies reference-counted ownership via `std::enable_shared_from_this` and `std::shared_ptr`, ensuring the object remains alive while the queued lambda holds a reference to it.

### File: LambdaCapturedThisQueuedAsync.cpp

```cpp
#include <functional>
#include <vector>
#include <memory>

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
        // FIXED: Capture shared_from_this() instead of raw this to maintain ownership
        auto this_shared = shared_from_this();
        queue.post([this_shared]() { this_shared->onTimerFired(); });
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
// timer against the shared queue, and returns. The Widget is now managed by
// a shared_ptr, so it remains alive while the queued lambda holds a reference
// to it, and is destroyed only after the lambda executes.
void handleRequest(TaskQueue& queue) {
    auto widget = std::make_shared<Widget>(42);
    widget->startTimer(queue);
} // widget shared_ptr goes out of scope, but the object is kept alive by the lambda

void runEventLoop(TaskQueue& queue) {
    handleRequest(queue);
    // The lambda captured earlier now runs, safely dereferencing the Widget
    // through the shared_ptr it captured.
    queue.runPending();
}

int main() {
    TaskQueue queue;
    runEventLoop(queue);
    return 0;
}
```

## Explanation
The fix eliminates the use-after-free by replacing raw pointer capture with shared ownership. `Widget` now inherits from `std::enable_shared_from_this<Widget>`, and in `startTimer()`, the lambda captures the result of `shared_from_this()` instead of the raw `this` pointer. This ensures the `Widget` object remains allocated while the queued lambda holds a reference to it. The callsite in `handleRequest()` changes from stack allocation to `std::make_shared<Widget>(42)`, which creates the Widget on the heap and wraps it in a `shared_ptr`. When `handleRequest()` returns, the local `shared_ptr` goes out of scope, but the reference count remains non-zero because the queued lambda holds a copy of the `shared_ptr`. Only after the lambda executes in `queue.runPending()` does the reference count drop to zero and the Widget is deleted. This pattern—deriving from `enable_shared_from_this` and capturing `shared_from_this()` in a lambda that escapes the current scope—is the standard C++ remedy for use-after-free in async/callback scenarios.

## Behaviour changes
- `Widget` is now heap-allocated via `std::make_shared()` instead of stack-allocated. Justification: Required to establish a `shared_ptr` that `enable_shared_from_this` can vend.
- `Widget` now inherits from `std::enable_shared_from_this<Widget>`. Justification: Required to implement reference-counted lifetime.
- The lambda captures a `shared_ptr<Widget>` (via `this_shared`) instead of a raw pointer. Justification: Maintains a reference count, preventing the object from being destroyed while the lambda is queued.
- Member access in the lambda changes from `this->onTimerFired()` to `this_shared->onTimerFired()`. Justification: Reflects the captured type being a smart pointer rather than a raw pointer.
- `#include <memory>` is added. Justification: Required for `std::shared_ptr` and `std::enable_shared_from_this`.
- `handleRequest()` callsite now uses `std::make_shared<Widget>(42)` instead of stack allocation. Justification: Required to ensure the Widget is owned by a `shared_ptr` so that `shared_from_this()` can work correctly.
- The external semantics remain unchanged: a Widget is created, its timer is armed, and it fires after the request handler completes.
