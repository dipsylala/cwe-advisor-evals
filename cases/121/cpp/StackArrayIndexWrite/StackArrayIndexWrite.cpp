#include <array>
#include <cstddef>
#include <cstdint>

struct Badge {
    std::array<std::uint8_t, 32> levels;
};

Badge buildBadge(std::size_t slot, std::uint8_t level) {
    Badge badge{};
    badge.levels[slot] = level;
    return badge;
}
