#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace birch::test {

inline std::string Mutf8(std::u16string_view text) {
    std::string result;
    for (const auto c : text) {
        if (c && c < 128U) result.push_back(static_cast<char>(c));
        else if (c < 2048U) {
            result.push_back(static_cast<char>(0xc0U | (c >> 6U)));
            result.push_back(static_cast<char>(0x80U | (c & 63U)));
        } else {
            result.push_back(static_cast<char>(0xe0U | (c >> 12U)));
            result.push_back(static_cast<char>(0x80U | ((c >> 6U) & 63U)));
            result.push_back(static_cast<char>(0x80U | (c & 63U)));
        }
    }
    return result;
}

inline std::u16string Utf16(std::string_view bytes) {
    std::u16string result;
    for (std::size_t i = 0; i < bytes.size();) {
        const auto first = static_cast<std::uint8_t>(bytes[i++]);
        std::uint32_t c = first;
        unsigned extra = 0;
        if (first >= 0xe0U && first < 0xf0U) { c &= 15U; extra = 2; }
        else if (first >= 0xc0U && first < 0xe0U) { c &= 31U; extra = 1; }
        else if (first >= 128U) throw std::runtime_error("invalid oracle MUTF8 lead");
        while (extra--) {
            const auto byte = static_cast<std::uint8_t>(bytes.at(i++));
            if ((byte & 0xc0U) != 0x80U) throw std::runtime_error("invalid oracle MUTF8 tail");
            c = (c << 6U) | (byte & 63U);
        }
        result.push_back(static_cast<char16_t>(c));
    }
    return result;
}

} // namespace birch::test
