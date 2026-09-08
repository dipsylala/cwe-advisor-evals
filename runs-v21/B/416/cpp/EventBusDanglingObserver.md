## Verdict

VULNERABLE - Confirmed Use After Free. The EventBus stores raw pointers to Observer objects with lifetimes bounded by caller scope. When an Observer is destroyed (stack frame exit), the stored pointer becomes dangling. Subsequent publish() calls dereference this freed memory at line 18.

## Source

**File: sensor_monitor.cpp, line 25-28**
```
SensorObserver observer;              // Stack-allocated
sharedBus().subscribe(&observer);     // Raw pointer stored
// observer destroyed here; EventBus pointer now dangling
```

**File: event_bus.cpp, line 23**
```
std::vector<Observer *> observers_;   // Stores raw pointers with no ownership model
```

## Fix

### File: event_bus.cpp

```cpp
#include <memory>
#include <vector>

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
        auto it = observers_.begin();
        while (it != observers_.end()) {
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
    // observer is kept alive by shared_ptr, destroyed here when it goes out of scope
    // EventBus holds weak_ptr; when observer is destroyed, lock() will detect it
}
```

## Explanation

The vulnerability arose because EventBus stored raw pointers (`std::vector<Observer *>`) to Observer objects whose lifetimes were not bound to the EventBus. When an Observer was destroyed, the pointer became dangling, and any subsequent publish() call dereferenced freed memory.

The fix applies the C++ weak_ptr pattern: EventBus now stores `std::vector<std::weak_ptr<Observer>>` instead of raw pointers. This requires callers to pass `std::shared_ptr<Observer>` to subscribe(), which the EventBus internally converts to weak_ptr.

In publish(), each weak_ptr is locked before use. The lock() method returns a shared_ptr if the Observer still exists, or nullptr if it has been destroyed. This achieves two safety properties:

1. **Automatic cleanup**: When an Observer is destroyed, its reference count drops and the weak_ptr detects this. The publish() loop removes dead entries via vector::erase().
2. **No stale access**: The if-init pattern (`if (auto observer = it->lock())`) ensures the check and the access are atomic—the observer cannot be destroyed between the lock() call and the onEvent() invocation.

The subscription pattern now requires heap allocation via std::make_shared, which shifts responsibility for lifetime to the subscriber. This is the correct ownership model for a registry: the EventBus does not own Observers, it merely holds weak references. When an Observer is destroyed, the EventBus detects and skips it without error.

API changes:
- subscribe() now accepts `std::shared_ptr<Observer>` instead of `Observer *`
- Callers must wrap Observers in shared_ptr (e.g., via std::make_shared)
- Dead observers are automatically removed during publish() (no explicit unsubscribe required, though it is still safe to call)

## Behaviour changes

**Breaking API change**: The subscribe() method signature changes from accepting `Observer *` to `std::shared_ptr<Observer>`. Callers must:
- Allocate Observers on the heap via `std::make_shared<ConcreteObserver>()`
- Pass the resulting shared_ptr to subscribe()

**Non-breaking behavioural change**: EventBus now tolerates Observer destruction. If an Observer is destroyed while still registered, the next publish() call cleanly removes the dead entry rather than crashing.

**Pre-fix behaviour**: Stack-allocated or otherwise short-lived Observers cause immediate memory corruption and undefined behaviour on publish().

**Post-fix behaviour**: Short-lived Observers are safely skipped; long-lived Observers continue to receive events until destroyed.

Compilation: C++17 or later (for structured bindings in if-init). All APIs used are standard library: std::shared_ptr, std::weak_ptr, weak_ptr::lock(), vector::erase(), and the iterator form of erase().

