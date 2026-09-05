## Verdict
Use-after-free confirmed. The `EventBus` stores raw pointers to `Observer` objects in a `std::vector`, but `monitorOnce()` subscribes a stack-allocated observer that is destroyed before its pointer is removed from the vector. Subsequent calls to `publish()` dereference the dangling pointer.

## Source
**event_bus.cpp, line 18**: `observer->onEvent(code);`

The vulnerability occurs because:
1. `EventBus::subscribe()` stores raw pointers: `observers_.push_back(observer);`
2. `sensor_monitor.cpp`, function `monitorOnce()` creates a stack-allocated `SensorObserver observer;`
3. The observer is subscribed: `sharedBus().subscribe(&observer);`
4. When `monitorOnce()` returns, the observer is destroyed but remains in the `observers_` vector
5. The next call to `publish()` dereferences the dangling pointer

## Fix
Replace raw pointers with `std::shared_ptr<Observer>` in `EventBus` to tie observer lifetime to subscription:

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
        for (const auto &observer : observers_) {
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

Update `sensor_monitor.cpp` to allocate the observer on the heap and pass a `shared_ptr`:

```cpp
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
    // observer's lifetime is managed by the shared_ptr.
    // It remains alive as long as it's referenced by sharedBus()
}
```

## Explanation
The fix ensures observer objects remain alive as long as they are referenced by the event bus. By using `std::shared_ptr`, the bus maintains shared ownership of each observer. When `monitorOnce()` ends, its local reference to the `shared_ptr` goes out of scope, but the bus's reference keeps the observer alive until it is explicitly removed or the bus is destroyed. This eliminates the dangling pointer dereference at line 18. The pattern also provides automatic cleanup: if an observer is later unsubscribed, the bus's reference is released, and the observer is freed when no other references exist.
