#include <cstddef>
#include <cstdint>
#include <span>

void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value);

void encodeTelemetry(std::span<std::uint8_t> packet, std::size_t advertisedLength, std::size_t index, std::uint8_t value) {
    writeSegmentByte(packet, advertisedLength, index, value);
}
