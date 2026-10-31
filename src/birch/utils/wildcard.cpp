#include "birch/utils/wildcard.h"

namespace birch::utils {

bool WildcardMatch(std::string_view value, std::string_view pattern) noexcept {
    std::size_t value_index = 0U;
    std::size_t pattern_index = 0U;
    std::size_t star_index = std::string_view::npos;
    std::size_t star_match = 0U;
    while (value_index < value.size()) {
        if (pattern_index < pattern.size() && pattern[pattern_index] == value[value_index]) {
            ++value_index;
            ++pattern_index;
        } else if (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
            while (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
                ++pattern_index;
            }
            star_index = pattern_index;
            star_match = value_index;
        } else if (star_index != std::string_view::npos) {
            pattern_index = star_index;
            value_index = ++star_match;
        } else {
            return false;
        }
    }
    while (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
        ++pattern_index;
    }
    return pattern_index == pattern.size();
}

} // namespace birch::utils
