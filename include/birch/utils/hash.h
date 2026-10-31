#pragma once

#include <cstdint>
#include <string_view>

namespace birch::utils {

[[nodiscard]] std::uint64_t StableHash64(std::string_view value,
                                         std::uint64_t seed = 0U) noexcept;

} // namespace birch::utils
