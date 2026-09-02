class Observer {
public:
    virtual ~Observer() = default;
    virtual void onEvent(int code) = 0;
};

class EventBus {
public:
    void subscribe(Observer *observer);
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
    SensorObserver observer;
    sharedBus().subscribe(&observer);
    // observer goes out of scope here without unsubscribing; sharedBus() keeps
    // the raw pointer and dereferences it on the next publish() call.
}
