#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <utility>

class Session {
public:
    explicit Session(std::string id) : id_(std::move(id)) {}
    void touch();

private:
    std::string id_;
};

class CallbackQueue {
public:
    void enqueue(std::function<void()> callback)
    {
        callbacks_.push(std::move(callback));
    }

private:
    std::queue<std::function<void()>> callbacks_;
};

void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    Session *raw = session.get();

    queue.enqueue([raw]() {
        // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
        raw->touch();
    });

    session.reset();
}
