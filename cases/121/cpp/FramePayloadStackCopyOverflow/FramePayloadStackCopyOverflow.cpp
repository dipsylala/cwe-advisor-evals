#include <array>
#include <cstddef>
#include <cstdint>

struct Frame {
    std::array<std::uint8_t, 32> payload;
    std::size_t length;
};

Frame buildFrame(const std::uint8_t *data, std::size_t dataLen) {
    Frame frame{};
    frame.length = dataLen;

    for (std::size_t i = 0; i < dataLen; i++) {
        // SAST FINDING: CWE-121 (Stack-based Buffer Overflow) reported here. Sink is the next statement.
        frame.payload[i] = data[i];
    }

    return frame;
}
