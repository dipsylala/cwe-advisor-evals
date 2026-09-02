#include <memory>
#include <stdexcept>
#include <string>

// Represents a pooled connection handle that must be re-armed with fresh
// configuration whenever the caller wants to switch targets mid-request.
class Resource {
public:
    explicit Resource(std::string endpoint) : endpoint_(std::move(endpoint)), bytesSent_(0) {}

    void send(const std::string& payload) {
        bytesSent_ += payload.size();
    }

    const std::string& endpoint() const { return endpoint_; }
    size_t bytesSent() const { return bytesSent_; }

private:
    std::string endpoint_;
    size_t bytesSent_;
};

// Sends a request body to primaryEndpoint, then re-points the connection at
// fallbackEndpoint and reports how many bytes the original send transferred.
size_t relayWithFallback(const std::string& primaryEndpoint,
                          const std::string& fallbackEndpoint,
                          const std::string& payload) {
    std::unique_ptr<Resource> resourcePtr = std::make_unique<Resource>(primaryEndpoint);

    // Grab a raw handle for use in this function's logging and metrics path.
    Resource* rawHandle = resourcePtr.get();
    rawHandle->send(payload);

    if (!fallbackEndpoint.empty()) {
        // Switching targets destroys the Resource that rawHandle still points at;
        // resourcePtr now owns a brand-new Resource for fallbackEndpoint.
        resourcePtr.reset(new Resource(fallbackEndpoint));
    }

    // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
    return rawHandle->bytesSent();
}
