## Verdict

Use after free: the lambda at line 32 captures a raw `this` pointer, but the Widget object is destroyed at line 53 (end of `handleRequest`) before the lambda executes at line 59. The queued lambda's dereference of `this->onTimerFired()` then operates on freed memory.

## Source

Line 32: `queue.post([this]() { this->onTimerFired(); });`

The lambda captures `this` by value as a raw pointer. The containing Widget object has automatic storage and is destroyed when `handleRequest` exits. By the time `runPending()` invokes the queued lambda, the Widget no longer exists, leaving `this` as a dangling pointer.

## Fix

Use `std::shared_ptr` to extend the Widget's lifetime for as long as any pending lambda holds a reference to it. Make Widget inherit from `std::enable_shared_from_this<Widget>`, capture `shared_from_this()` in the lambda instead of a raw `this`, and create the Widget as a shared_ptr:

```cpp
#include <functional>
#include <vector>
#include <memory>

// TaskQueue unchanged (as shown in original)
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

// Widget now inherits from enable_shared_from_this
class Widget : public std::enable_shared_from_this<Widget> {
public:
    explicit Widget(int id) : id_(id) {}

    void startTimer(TaskQueue& queue) {
        // Capture shared_ptr to self instead of raw this
        auto self = shared_from_this();
        queue.post([self]() { self->onTimerFired(); });
    }

    void onTimerFired() {
        lastFiredId_ = id_;
    }

    int lastFiredId() const { return lastFiredId_; }

private:
    int id_;
    int lastFiredId_ = 0;
};

void handleRequest(TaskQueue& queue) {
    // Create Widget as shared_ptr so shared_from_this() is valid
    auto widget = std::make_shared<Widget>(42);
    widget->startTimer(queue);
    // Widget is not destroyed here; the queued lambda holds a reference
}

void runEventLoop(TaskQueue& queue) {
    handleRequest(queue);
    queue.runPending();
}

int main() {
    TaskQueue queue;
    runEventLoop(queue);
    return 0;
}
```

## Explanation

The root cause is a lifetime mismatch: the lambda is posted to an async queue before the object it references is destroyed, but the lambda is not executed until after destruction. Capturing a raw `this` pointer cannot detect or prevent this.

The fix uses `std::enable_shared_from_this<Widget>` and `shared_from_this()` to convert the raw `this` pointer into a `std::shared_ptr`. The lambda captures this shared_ptr, incrementing the reference count. The Widget object persists in heap memory for as long as any pending lambda holds the shared_ptr, preventing use-after-free when the lambda executes. Once the lambda completes and the shared_ptr is destroyed, the Widget is freed. This is a standard pattern for asynchronous operations that capture object state: manage the object's lifetime via shared ownership, not automatic storage.
