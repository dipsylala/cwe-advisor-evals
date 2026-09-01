#include <memory>
#include <string>

class ClientConnection {
public:
    void send(const std::string& message);
};

class Notifier {
public:
    explicit Notifier(std::weak_ptr<ClientConnection> connection) : connection_(connection) {}

    void notify(const std::string& message) {
        auto connection = connection_.lock();
        connection->send(message);
    }

private:
    std::weak_ptr<ClientConnection> connection_;
};
