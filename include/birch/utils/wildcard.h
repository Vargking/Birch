#pragma once

#include <string_view>

namespace birch::utils {

[[nodiscard]] bool WildcardMatch(std::string_view value,
                                 std::string_view pattern) noexcept;

} // namespace birch::utils
