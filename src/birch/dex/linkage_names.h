#pragma once

#include <map>
#include <string>
#include <string_view>

namespace birch::dex::detail {

inline std::string Translate(std::string_view value,
    const std::map<std::string, std::string, std::less<>>& classes) {
    std::string result;
    for (std::size_t cursor = 0; cursor < value.size();) {
        if (value[cursor] != 'L') { result += value[cursor++]; continue; }
        const auto end = value.find(';', cursor);
        if (end == std::string_view::npos) { result += value.substr(cursor); break; }
        const auto descriptor = value.substr(cursor, end + 1U - cursor);
        const auto found = classes.find(descriptor);
        result += found == classes.end() ? std::string(descriptor) : found->second;
        cursor = end + 1U;
    }
    return result;
}

inline std::string Rename(const std::string& name,
    const std::map<std::string, std::string, std::less<>>& names) {
    const auto found = names.find(name);
    return found == names.end() ? name : found->second;
}

inline std::string_view Package(std::string_view descriptor) {
    const auto end = descriptor.rfind('/');
    return end == std::string_view::npos ? std::string_view{} : descriptor.substr(0, end);
}

} // namespace birch::dex::detail
