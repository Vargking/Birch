#include "birch/utils/hash.h"

namespace birch::utils {

std::uint64_t StableHash64(std::string_view value, std::uint64_t seed) noexcept {
    std::uint64_t hash = 1469598103934665603ULL ^ seed;
    for (const auto byte : value) {
        hash ^= static_cast<std::uint8_t>(byte);
        hash *= 1099511628211ULL;
    }
    return hash;
}

} // namespace birch::utils
