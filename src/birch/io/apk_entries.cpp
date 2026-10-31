#include "birch/io/apk_entries.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace birch::io {

bool IsDexEntryName(std::string_view name) noexcept {
    if (name == "classes.dex") return true;
    if (!name.starts_with("classes") || !name.ends_with(".dex")) return false;
    const auto digits = name.substr(7U, name.size() - 11U);
    return !digits.empty() && std::all_of(digits.begin(), digits.end(), [](char value) {
        return value >= '0' && value <= '9';
    });
}

std::uint32_t DexEntryOrdinal(std::string_view name) {
    if (!IsDexEntryName(name)) {
        throw std::invalid_argument("not an APK DEX entry name: " + std::string(name));
    }
    if (name == "classes.dex") return 1U;
    const auto digits = name.substr(7U, name.size() - 11U);
    if (digits.front() == '0') {
        throw std::invalid_argument("noncanonical secondary DEX entry name: " + std::string(name));
    }
    std::uint64_t value = 0U;
    for (const auto digit : digits) {
        value = value * 10U + static_cast<unsigned>(digit - '0');
        if (value > std::numeric_limits<std::uint32_t>::max()) {
            throw std::invalid_argument("APK DEX ordinal overflows uint32");
        }
    }
    if (value < 2U) throw std::invalid_argument("secondary DEX ordinal must be at least 2");
    return static_cast<std::uint32_t>(value);
}

std::vector<std::string> DexEntryNames(const guard::ZipArchive& archive) {
    std::vector<std::string> result;
    for (const auto& entry : archive.entries()) {
        if (IsDexEntryName(entry.name)) {
            // Validation cannot be deferred to the sorting comparator: a
            // single candidate never reaches it, and invalid names must not
            // silently become untransformed assets.
            (void)DexEntryOrdinal(entry.name);
            result.push_back(entry.name);
        }
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return DexEntryOrdinal(left) < DexEntryOrdinal(right);
    });
    for (std::size_t index = 1U; index < result.size(); ++index) {
        if (DexEntryOrdinal(result[index - 1U]) == DexEntryOrdinal(result[index])) {
            throw std::runtime_error("duplicate APK DEX ordinal");
        }
    }
    return result;
}

std::string NextDexEntryName(const guard::ZipArchive& archive) {
    const auto names = DexEntryNames(archive);
    if (names.empty()) return "classes.dex";
    const auto ordinal = DexEntryOrdinal(names.back());
    if (ordinal == std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("APK DEX ordinal space exhausted");
    }
    return "classes" + std::to_string(ordinal + 1U) + ".dex";
}

} // namespace birch::io
