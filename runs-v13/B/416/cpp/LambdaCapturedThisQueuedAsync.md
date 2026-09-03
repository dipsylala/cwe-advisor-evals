## Verdict

**CWE-416 (Use After Free) — Confirmed**

A lambda captures `this` (raw pointer) and is queued in `startTimer()`, but the Widget object is destroyed before the queued lambda runs in `runPending()`. The lambda then dereferences a dangling pointer.

## Source

File: `evals/cases/416/cpp/LambdaCapturedThisQueuedAsync/LambdaCapturedThisQueuedAsync.cpp`

Line 32: `queue.post([this]() { this->onTimerFired(); });`

Data flow:
1. Widget created in `handleRequest()` (line 51)
2. `widget.startTimer(queue)` posts lambda with `[this]` capture (line 32)
3. Widget destroyed at end of `handleRequest()` (line 53)
4. Lambda stored in queue still holds dangling raw pointer
5. `queue.runPending()` executes lambda, dereferencing destroyed object (line 59)

## Fix

The Widget class must derive from `std::enable_shared_from_this<Widget>` and the lambda must capture an owning `shared_ptr` instead of a raw `this` pointer.

**Fixed code:**

```cpp
#include <functional>
#include <vector>
#include <memory>

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
        // Capture shared_ptr instead of raw this to extend Widget's lifetime
        queue.post([this_ptr = shared_from_this()]() { this_ptr->onTimerFired(); });
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
// timer against the shared queue, and returns. The Widget is kept alive by
// the shared_ptr captured in the lambda, so it is not destroyed until the
// queued lambda has been executed.
void handleRequest(TaskQueue& queue) {
    auto widget = std::make_shared<Widget>(42);
    widget->startTimer(queue);
}

void runEventLoop(TaskQueue& queue) {
    handleRequest(queue);
    // The lambda captured earlier now runs safely, with a valid Widget
    queue.runPending();
}

int main() {
    TaskQueue queue;
    runEventLoop(queue);
    return 0;
}
```

## Explanation

The vulnerability occurs because the lambda `[this]()` captures a raw pointer to the Widget, which is then destroyed before the lambda executes. The fix replaces the raw `this` capture with a captured `shared_ptr` obtained via `shared_from_this()`.

Three changes enable this:

1. **Class inheritance**: Widget now derives from `std::enable_shared_from_this<Widget>`, which allows member functions to obtain an owning `shared_ptr` to themselves via `shared_from_this()`.

2. **Capture replacement**: The lambda changes from `[this]()` to `[this_ptr = shared_from_this()]()`. This captures an owning `shared_ptr` instead of a raw pointer. By capturing the `shared_ptr`, the lambda holds a reference to the Widget, preventing it from being destroyed until the lambda executes and the `shared_ptr` leaves scope.

3. **Memory management**: The Widget is now created via `std::make_shared<Widget>()` in `handleRequest()`, which is the correct factory for objects that will be managed by `shared_ptr`. The owning `shared_ptr` in the lambda ensures the Widget's lifetime is extended to cover the queued callback.

When `queue.runPending()` executes the lambda, the Widget is guaranteed to still exist because the captured `shared_ptr` holds a reference to it. After the lambda completes, the `shared_ptr` is destroyed, and if no other references remain, the Widget is deallocated.

## Behaviour changes

- The Widget must be created as `std::make_shared<Widget>()` rather than on the stack, because `enable_shared_from_this<T>::shared_from_this()` requires the object to already be owned by a `shared_ptr`. Calling `shared_from_this()` on an object not managed by `shared_ptr` throws `std::bad_weak_ptr`.
- Widget's lifetime now extends until the queued lambda has executed, rather than ending immediately when `handleRequest()` returns. This is the intended fix: the callback now runs with a valid object.
- The lambda is no longer copyable if it was not copyable before (no change in this case, as the lambda was already copyable), but moving an owning `shared_ptr` into the capture remains efficient.
