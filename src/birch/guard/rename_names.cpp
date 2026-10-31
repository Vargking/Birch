#include "rename_names.h"

#include "birch/utils/hash.h"

#include <algorithm>
#include <map>
#include <stdexcept>
#include <utility>

namespace birch::guard::detail {

std::vector<std::string> NameGenerator::DictionaryTokens(std::string_view dictionary) {
    std::vector<std::string> result;
    std::set<std::string, std::less<>> seen;
    for (std::size_t cursor = 0; cursor < dictionary.size();) {
        const auto first = static_cast<std::uint8_t>(dictionary[cursor]);
        std::size_t width = 0U;
        std::uint32_t codepoint = 0U;
        if (first <= 0x7fU) { width = 1U; codepoint = first; }
        else if (first >= 0xc2U && first <= 0xdfU) { width = 2U; codepoint = first & 0x1fU; }
        else if (first >= 0xe0U && first <= 0xefU) { width = 3U; codepoint = first & 0x0fU; }
        else if (first >= 0xf0U && first <= 0xf4U) { width = 4U; codepoint = first & 0x07U; }
        else throw std::invalid_argument("rename dictionary contains invalid UTF-8");
        if (cursor + width > dictionary.size()) throw std::invalid_argument("rename dictionary UTF-8 is truncated");
        for (std::size_t i = 1U; i < width; ++i) {
            const auto next = static_cast<std::uint8_t>(dictionary[cursor + i]);
            if ((next & 0xc0U) != 0x80U) throw std::invalid_argument("rename dictionary contains invalid UTF-8 continuation");
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if ((width == 2U && codepoint < 0x80U) ||
            (width == 3U && codepoint < 0x800U) ||
            (width == 4U && codepoint < 0x10000U)) {
            throw std::invalid_argument("rename dictionary contains overlong UTF-8");
        }
        if (codepoint == 0U || codepoint > 0xffffU ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
            throw std::invalid_argument("rename dictionary entries must be non-zero BMP code points");
        }
        if (codepoint == '/' || codepoint == '.' || codepoint == ';' || codepoint == '[' ||
            codepoint == '<' || codepoint == '>' || codepoint == '(' || codepoint == ')') {
            throw std::invalid_argument("rename dictionary contains a DEX identifier delimiter");
        }
        std::string token(dictionary.substr(cursor, width));
        if (seen.insert(token).second) result.push_back(std::move(token));
        cursor += width;
    }
    if (result.empty()) throw std::invalid_argument("rename dictionary has no usable symbols");
    return result;
}

std::uint32_t NameGenerator::Mutf8Utf16Length(std::string_view value) {
    std::uint32_t units = 0U;
    for (std::size_t cursor = 0; cursor < value.size();) {
        const auto first = static_cast<std::uint8_t>(value[cursor]);
        std::size_t width = first <= 0x7fU ? 1U : first <= 0xdfU ? 2U : 3U;
        if (cursor + width > value.size()) throw std::invalid_argument("generated MUTF-8 name is truncated");
        for (std::size_t i = 1U; i < width; ++i) {
            if ((static_cast<std::uint8_t>(value[cursor + i]) & 0xc0U) != 0x80U) {
                throw std::invalid_argument("generated MUTF-8 name has invalid continuation");
            }
        }
        ++units;
        cursor += width;
    }
    return units;
}

std::string NameGenerator::StableResourceName(std::string_view value, std::uint64_t seed, std::size_t max_length) {
    auto hash = utils::StableHash64(value, seed);
    static constexpr char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    if (max_length == 0U) throw std::runtime_error("resource name has no writable length");
    std::string result = max_length == 1U ? std::string(1U, digits[hash % 36U]) : "r";
    if (max_length > 1U) do { result.push_back(digits[hash % 36U]); hash /= 36U; } while (hash != 0U && result.size() < std::min<std::size_t>(max_length, 10U));
    return result;
}

std::string NameGenerator::DictionaryResourceName(std::string_view value, std::string_view dictionary,
                                   std::uint64_t seed, std::size_t max_length) {
    if (dictionary.empty()) return NameGenerator::StableResourceName(value, seed, max_length);
    if (max_length == 0U) throw std::runtime_error("resource name has no writable length");
    std::uint64_t hash = utils::StableHash64(value, seed);
    std::string starters;
    for (const auto character : dictionary) {
        if ((character >= 'a' && character <= 'z') || character == '_') {
            starters.push_back(character);
        }
    }
    if (starters.empty()) {
        throw std::invalid_argument("resource dictionary has no legal initial character");
    }
    std::string result(1U, starters[hash % starters.size()]);
    hash = hash / starters.size() + 0x9e3779b97f4a7c15ULL;
    for (std::size_t i = 1U; i < max_length; ++i) {
        result.push_back(dictionary[hash % dictionary.size()]);
        hash = hash / dictionary.size() + 0x9e3779b97f4a7c15ULL;
    }
    return result;
}

std::string NameGenerator::StableDexName(std::string_view original, std::string_view prefix,
                          const std::vector<std::string>& dictionary, std::uint64_t seed,
                          std::set<std::string, std::less<>>& used) {
    for (std::size_t width = 1U; width <= 128U; ++width) {
        auto hash = utils::StableHash64(original, seed);
        std::string result(prefix);
        // Protected descriptors intentionally use one synthetic package
        // component.  Keeping the package depth fixed prevents the output
        // from leaking source hierarchy and avoids the misleading b/x/x
        // shapes produced by the former per-class depth mixer.
        hash = hash / 5U + 0x9e3779b97f4a7c15ULL;
        for (std::size_t i = 0; i < width; ++i) {
            result += dictionary[hash % dictionary.size()];
            hash = hash / dictionary.size() + 0x9e3779b97f4a7c15ULL;
        }
        result.push_back(';');
        if (result != original && !used.contains(result)) { used.insert(result); return result; }
    }
    throw std::runtime_error("unable to generate collision-free DEX name: " + std::string(original));
}

std::string NameGenerator::NormalizedRenamePrefix(std::string_view configured) {
    std::string value(configured);
    while (!value.empty() && value.front() == 'L') value.erase(value.begin());
    while (!value.empty() && value.back() == '/') value.pop_back();
    const auto slash = value.find('/');
    if (slash != std::string::npos) value.resize(slash);
    if (value.empty()) value = "b";
    return "L" + value + "/";
}

std::string NameGenerator::StableMemberName(std::string_view original,
                             const std::vector<std::string>& dictionary,
                             std::uint64_t seed,
                             std::set<std::string, std::less<>>& used) {
    for (std::size_t width = 1U; width <= 128U; ++width) {
        auto hash = utils::StableHash64(original, seed);
        std::string result;
        for (std::size_t i = 0; i < width; ++i) {
            result += dictionary[hash % dictionary.size()];
            hash = hash / dictionary.size() + 0x9e3779b97f4a7c15ULL;
        }
        if (result != original && !used.contains(result)) { used.insert(result); return result; }
    }
    throw std::runtime_error("unable to generate collision-free member name: " + std::string(original));
}

bool NameGenerator::IsSpecialMethod(std::string_view name) {
    return name == "<init>" || name == "<clinit>";
}

} // namespace birch::guard::detail

