#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace birch::guard {

inline constexpr std::string_view kStringHelperMethodPrefix = "$s";

[[nodiscard]] std::string RuntimeStringMethodName(std::string_view value,
                                                  std::uint64_t seed);

} // namespace birch::guard
