## Verdict

Exploitable. The `EventBus` stores raw pointers in `observers_` (line 23 of event_bus.cpp) and dereferences them in `publish()` at line 18. The `SensorObserver` in `sensor_monitor.cpp` is stack-allocated (line 25) and destroyed when `monitorOnce()` returns (line 29), leaving a dangling pointer in `observers_`. The next `publish()` call dereferences that invalid pointer, triggering use-after-free.

## Source

**Data flow**:
- Source: Stack-allocated `SensorObserver observer` (sensor_monitor.cpp:25)
- Flow: `sharedBus().subscribe(&observer)` (sensor_monitor.cpp:26) stores raw pointer into `observers_` vector (event_bus.cpp:12)
- Sink: `observer->onEvent(code)` dereference at event_bus.cpp:18

**Lifetime problem**: `observer` is destroyed at function exit (sensor_monitor.cpp:29) while `EventBus::observers_` retains and later dereferences the dangling pointer.

## Fix

**Vulnerable code (event_bus.cpp)**:
```cpp
class EventBus {
public:
    void subscribe(Observer *observer) {
        observers_.push_back(observer);
    }

    void publish(int code) {
        for (Observer *observer : observers_) {
            // VULNERABILITY: observer may point to destroyed object
            observer->onEvent(code);
        }
    }

private:
    std::vector<Observer *> observers_;
};
```

**Fixed code (event_bus.cpp)**:
```cpp
#include <memory>

class EventBus {
public:
    void subscribe(std::shared_ptr<Observer> observer) {
        observers_.push_back(observer);
    }

    void publish(int code) {
        // Remove expired observers
        observers_.erase(
            std::remove_if(observers_.begin(), observers_.end(),
                          [](const std::weak_ptr<Observer>& obs) { return obs.expired(); }),
            observers_.end());
        
        for (const auto &observer_weak : observers_) {
            if (auto observer = observer_weak.lock()) {
                observer->onEvent(code);
            }
        }
    }

private:
    std::vector<std::weak_ptr<Observer>> observers_;
};
```

**Updated client code (sensor_monitor.cpp)** to enable safe ownership:
```cpp
void monitorOnce() {
    auto observer = std::make_shared<SensorObserver>();
    sharedBus().subscribe(observer);
    // observer is held by both the shared_ptr here and the weak_ptr in EventBus
    // When monitorOnce() returns, the local shared_ptr is destroyed, but the object
    // remains alive as long as EventBus needs it (via the weak_ptr's reference count)
}
```

## Explanation

The fix converts `EventBus::observers_` from a vector of raw pointers to a vector of `std::weak_ptr<Observer>`. This allows observers to manage their own lifetime independently: when an observer is destroyed, its `shared_ptr` reference count drops, and the `weak_ptr` in the EventBus automatically detects this via `expired()` or `lock()` returning `nullptr`.

The `subscribe()` method now requires a `std::shared_ptr<Observer>`, which signifies that the caller is transferring ownership responsibility to the EventBus (or at least ensuring the observer stays alive while subscribed). Inside `publish()`, each weak_ptr is locked before use; if the observer has been destroyed, `lock()` returns `nullptr` and the call is skipped.

The cleanup step (removing expired observers during `publish()`) prevents the vector from growing indefinitely with dead pointers.

In the client code (`sensor_monitor.cpp`), `std::make_shared<SensorObserver>()` creates the observer on the heap with a `shared_ptr`, ensuring it survives as long as the EventBus holds a reference to it via `weak_ptr`. When the local `shared_ptr` goes out of scope, the object is only destroyed if the EventBus has already removed its weak reference (either by unsubscribing or cleanup).

## Behaviour changes

**Changed behavior (intentional, required for the fix)**:
1. `subscribe()` signature changed from `void subscribe(Observer *observer)` to `void subscribe(std::shared_ptr<Observer> observer)` - callers must now provide a `shared_ptr` instead of a raw pointer. This is necessary to establish shared ownership semantics and prevent the use-after-free.

2. Observers are stored as `std::weak_ptr<Observer>` instead of raw pointers - weak pointers do not extend object lifetime, so observers can be destroyed independently and safely.

3. `publish()` now silently skips observers whose `weak_ptr::lock()` fails (returned observers already destroyed), instead of dereferencing a dangling pointer. This prevents the crash but means dead observers are simply not notified.

4. Memory efficiency change: `publish()` now calls `erase()` with `std::remove_if()` to clean up expired pointers during iteration. This keeps the vector from accumulating dead weak_ptrs over time, though it introduces a small O(n) cleanup cost per publish.

**Preserved behavior**:
- The virtual function call `observer->onEvent(code)` still occurs for living observers
- Return value of `publish()` unchanged (void)
- No change to the singleton `sharedBus()` implementation
