# CWE-416: Use After Free

## Verdict

exploitable

## Location

File: `evals/cases/416/cpp/LambdaCapturedThisQueuedAsync/LambdaCapturedThisQueuedAsync.cpp`
Lines: 32 (sink), 23-33 (vulnerable pattern), 50-53 (call site requiring change)

## Source

Widget object created on the stack in `handleRequest()` at line 51.

## Sink

Lambda capturing raw `this` pointer, posted to task queue at line 32 in `startTimer()`. The lambda dereferences `this` in `onTimerFired()` after the Widget object has been destroyed.

## Fix

**Vulnerable code (line 23-33):**
```cpp
class Widget {
public:
    explicit Widget(int id) : id_(id) {}

    void startTimer(TaskQueue& queue) {
        // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
        queue.post([this]() { this->onTimerFired(); });
    }
```

**Fixed code:**
```cpp
class Widget : public std::enable_shared_from_this<Widget> {
public:
    explicit Widget(int id) : id_(id) {}

    void startTimer(TaskQueue& queue) {
        queue.post([this_owner = shared_from_this()]() { this_owner->onTimerFired(); });
    }
```

**Vulnerable code (line 50-53):**
```cpp
void handleRequest(TaskQueue& queue) {
    Widget widget(42);
    widget.startTimer(queue);
}
```

**Fixed code:**
```cpp
void handleRequest(TaskQueue& queue) {
    auto widget = std::make_shared<Widget>(42);
    widget->startTimer(queue);
}
```

**Additional required change (line 1-2):**
```cpp
#include <functional>
#include <vector>
#include <memory>
```

## Explanation

The vulnerability occurs because the lambda captures a raw `this` pointer at the time `startTimer()` is called, but the Widget object is destroyed when `handleRequest()` returns. The queued lambda then executes in `runPending()` after the Widget has been freed, dereferencing a dangling pointer. The fix uses `std::enable_shared_from_this` and captures `shared_from_this()` instead of a raw `this` pointer. This creates a shared-ownership reference to the Widget through the lambda's capture, extending the Widget's lifetime until the lambda is destroyed. The Widget is now created as a `std::shared_ptr` in `handleRequest()`, which allows `shared_from_this()` to return a copy of the owning pointer. When `handleRequest()` returns, the local `shared_ptr` goes out of scope, but the copy held by the lambda keeps the Widget alive. Once the lambda runs and is cleaned up by `runPending()`, the Widget is properly destroyed when all shared pointers are released.

## Behaviour changes

- Added `#include <memory>` for `std::shared_ptr`, `std::make_shared`, and `std::enable_shared_from_this`.
- Widget now inherits from `std::enable_shared_from_this<Widget>`, adding a weak-pointer back-reference for ownership tracking but no overhead to the object size in typical implementations.
- `handleRequest()` now creates Widget via `std::make_shared<Widget>(42)` instead of stack allocation. This changes the Widget's storage from stack to heap, but ownership semantics are now explicit and safe.
- Lambda capture changed from `[this]` (raw pointer) to `[this_owner = shared_from_this()]` (shared ownership). The lambda now keeps a copy of the shared pointer, extending the Widget's lifetime. Access pattern changes from `this->onTimerFired()` to `this_owner->onTimerFired()`, but the semantic is equivalent and now safe.
- Widget will not be destroyed at line 53 in the original code; instead, it is destroyed after the queued lambda completes and all shared pointers are released.

## Confidence

high

## Library Recommendation

none - the fix uses only C++17 standard library components (`std::shared_ptr`, `std::make_shared`, `std::enable_shared_from_this`) that are part of the language standard library.

## Verification

Manual syntax check performed: all identifiers verified against C++17 standard library and language rules. New names introduced: `std::enable_shared_from_this` (class template from `<memory>`), `std::make_shared` (function from `<memory>`), `shared_from_this()` (member function from `enable_shared_from_this`), `std::shared_ptr` (class template from `<memory>`). All are standard library components available in C++11 and later. Lambda structured binding syntax `[this_owner = shared_from_this()]` is valid C++17 init-capture. No compiler was available in the evaluation environment to verify compilation; however, the fix is syntactically valid against C++17 standard and follows established patterns for `enable_shared_from_this` usage documented in the C++ standard.

## Assumptions

No assumptions required. The data flow is explicit in the provided code: the Widget is created, a lambda capturing `this` is posted to the queue, the Widget is destroyed at function exit, and the lambda is executed later with a dangling pointer. The fix is based directly on the C++ specific guidance in cwe/416/cpp/INDEX.md which explicitly prescribes `std::enable_shared_from_this` and `shared_from_this()` for this exact pattern of lambdas capturing `this` in queued/asynchronous callbacks.

