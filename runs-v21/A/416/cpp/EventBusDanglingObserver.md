## Verdict

CONFIRMED. The EventBus uses raw pointers to store observers without maintaining ownership. When an observer object is destroyed while the EventBus still holds a pointer to it, dereferencing that pointer in `publish()` results in use-after-free.

## Source

The vulnerability occurs across two files:

**event_bus.cpp (line 18):** The `publish()` method dereferences raw observer pointers that may have become dangling.

**sensor_monitor.cpp (lines 24-29):** A local observer is subscribed to the shared EventBus, then destroyed when the function returns, leaving a dangling pointer in the bus's internal vector.

The root cause is at line 12 in event_bus.cpp: `std::vector<Observer *> observers_;` stores non-owning raw pointers.

## Fix

### File: event_bus.cpp

```cpp
#include <vector>
#include <memory>

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
        for (std::shared_ptr<Observer> observer : observers_) {
            observer->onEvent(code);
        }
    }

private:
    std::vector<std::shared_ptr<Observer>> observers_;
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
}
```

## Explanation

The vulnerability is a use-after-free (CWE-416) caused by storing non-owning raw pointers in the EventBus. When an observer goes out of scope, it is destroyed while the EventBus still holds a dangling pointer to it. Subsequent calls to `publish()` dereference this dangling pointer.

The fix replaces raw pointers with `std::shared_ptr<Observer>`:

1. **EventBus::subscribe()** accepts a `std::shared_ptr<Observer>` instead of a raw pointer, establishing shared ownership.
2. **observers_ vector** stores `std::shared_ptr<Observer>` instead of raw pointers, ensuring observers remain alive as long as the EventBus holds references to them.
3. **sensor_monitor.cpp** creates the observer using `std::make_shared<SensorObserver>()`, returning a `shared_ptr` that can be passed to `subscribe()`.

With this change, the observer's lifetime is extended by the EventBus's reference count. The object is only destroyed after the EventBus removes the pointer from its vector and all other references are released, eliminating the use-after-free.
