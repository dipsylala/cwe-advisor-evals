## Verdict
Confirmed CWE-416 (Use After Free) at line 18 of event_bus.cpp. The EventBus stores raw pointers to Observer objects without validating their lifetime. When an observer is deleted while still referenced in the observers_ vector, calling publish() dereferences the dangling pointer.

## Source
The vulnerability spans two files:
- **event_bus.cpp**: EventBus::publish() iterates through a vector of raw Observer pointers and dereferences them without checking validity.
- **sensor_monitor.cpp**: monitorOnce() passes a stack-allocated SensorObserver to EventBus::subscribe(), then the observer goes out of scope while EventBus still holds its pointer.

The call chain: monitorOnce() → subscribe(raw_pointer) → [observer destroyed] → publish() → dereference(dangling_pointer).

## Fix

### File: event_bus.cpp
```cpp
#include <vector>
#include <memory>
#include <algorithm>

class Observer {
public:
    virtual ~Observer() = default;
    virtual void onEvent(int code) = 0;
};

class EventBus {
public:
    void subscribe(std::shared_ptr<Observer> observer) {
        observers_.push_back(observer);
    }

    void publish(int code) {
        for (auto it = observers_.begin(); it != observers_.end();) {
            if (auto observer = it->lock()) {
                observer->onEvent(code);
                ++it;
            } else {
                it = observers_.erase(it);
            }
        }
    }

private:
    std::vector<std::weak_ptr<Observer>> observers_;
};

EventBus &sharedBus() {
    static EventBus bus;
    return bus;
}
```

### File: sensor_monitor.cpp
```cpp
#include <memory>

class Observer {
public:
    virtual ~Observer() = default;
    virtual void onEvent(int code) = 0;
};

class EventBus {
public:
    void subscribe(std::shared_ptr<Observer> observer);
    void publish(int code);
};

EventBus &sharedBus();

class SensorObserver : public Observer {
public:
    void onEvent(int code) override {
        lastCode = code;
    }

    int lastCode = 0;
};

void monitorOnce() {
    auto observer = std::make_shared<SensorObserver>();
    sharedBus().subscribe(observer);
    // observer now owned by shared_ptr; when this scope exits, the reference
    // is released. If EventBus holds the last reference, observer lives until
    // removed from observers_ vector. weak_ptr in EventBus detects when the
    // observer is destroyed and skips it on next publish().
}
```

## Explanation
The fix uses `std::weak_ptr` in EventBus to detect when subscribed observers are destroyed. This prevents use-after-free:

1. **subscribe() now takes `std::shared_ptr<Observer>`** instead of a raw pointer, enabling proper lifetime tracking.
2. **observers_ stores `std::weak_ptr<Observer>`** instead of raw pointers, allowing automatic detection of destroyed objects.
3. **publish() validates each pointer with `lock()`** before dereferencing. If `lock()` returns null (observer was deleted), that entry is erased and skipped.
4. **sensor_monitor.cpp uses `std::make_shared`** to create the observer as a shared_ptr and pass it to EventBus.

When monitorOnce() returns, the observer's reference count is decremented. If EventBus holds the only remaining reference (via shared_ptr semantics), the observer stays alive. When it is finally destroyed, the weak_ptr in the observers_ vector detects the destruction on the next publish() call and safely removes it. This prevents the dangling pointer dereference at line 18.
