#pragma once
#include <string_view>

namespace birch::guard::detail {
// Exact registered IDs only: an unknown pass must never receive a plausible
// generic explanation that could be mistaken for implemented protection.
[[nodiscard]] std::string_view DescribeTechnique(std::string_view id);
}
