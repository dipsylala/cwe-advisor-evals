## Verdict

The finding is a real use-after-free vulnerability. Line 32 captures `this` in a lambda posted to an asynchronous task queue. The Widget object is destroyed before the queued lambda executes (at line 53 in `handleRequest`), leaving `this->onTimerFired()` dereferencing a dangling pointer when `runPending()` eventually runs the task.

## Source

The vulnerability lies in the lambda capture on line 32:

```cpp
queue.post([this]() { this->onTimerFired(); });
```

The lambda is captured with `[this]`, which stores a raw pointer to the Widget instance. The Widget is a local variable in `handleRequest()` and is destroyed at the end of that function (line 53), but the lambda remains queued in the TaskQueue and executes later in `runEventLoop()` at line 59, after the object has been deallocated.

## Fix

Replace the raw `this` capture with a `shared_ptr` to extend the Widget's lifetime:

1. Make Widget derive from `std::enable_shared_from_this<Widget>`:
   ```cpp
   class Widget : public std::enable_shared_from_this<Widget> {
   ```

2. In `startTimer()`, capture a shared_ptr to self instead of raw `this`:
   ```cpp
   void startTimer(TaskQueue& queue) {
       auto self = shared_from_this();
       queue.post([self]() { self->onTimerFired(); });
   }
   ```

3. In `handleRequest()`, create the Widget as a shared_ptr:
   ```cpp
   void handleRequest(TaskQueue& queue) {
       auto widget = std::make_shared<Widget>(42);
       widget->startTimer(queue);
   }
   ```

The shared_ptr capture keeps the Widget alive as long as the lambda exists, preventing the use-after-free.

## Explanation

CWE-416 use-after-free in asynchronous code occurs when an object is destroyed while an enqueued callback still holds a reference to it. Raw `this` pointers are particularly vulnerable in deferred execution patterns because the object's lifetime is under the caller's control, not the async system's.

The fix uses `shared_ptr` and `enable_shared_from_this` to transfer ownership semantics: the queued lambda now holds a reference that keeps the object alive until the lambda completes. This is idiomatic C++ for async callbacks and is the standard defense against this pattern.

`shared_from_this()` must be called only on an object already owned by at least one `shared_ptr`; passing the Widget into `handleRequest` as a `shared_ptr` instead of creating it on the stack satisfies that requirement.
