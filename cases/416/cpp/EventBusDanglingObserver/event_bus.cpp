#include <vector>

class Observer {
public:
    virtual ~Observer() = default;
    virtual void onEvent(int code) = 0;
};

class EventBus {
public:
    void subscribe(Observer *observer) {
        observers_.push_back(observer);
    }

    void publish(int code) {
        for (Observer *observer : observers_) {
            // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
            observer->onEvent(code);
        }
    }

private:
    std::vector<Observer *> observers_;
};

EventBus &sharedBus() {
    static EventBus bus;
    return bus;
}
