#pragma once

#include "birch/guard/config.h"

#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace birch::guard::detail {

// Deterministic, collision-checked names; no APK or rename-plan dependencies.
class NameGenerator final {
public:
    static std::vector<std::string> DictionaryTokens(std::string_view dictionary);

    static std::uint32_t Mutf8Utf16Length(std::string_view value);

    static std::string StableResourceName(std::string_view value, std::uint64_t seed, std::size_t max_length);

    static std::string DictionaryResourceName(std::string_view value, std::string_view dictionary,
                                       std::uint64_t seed, std::size_t max_length);

    static std::string StableDexName(std::string_view original, std::string_view prefix,
                              const std::vector<std::string>& dictionary, std::uint64_t seed,
                              std::set<std::string, std::less<>>& used);

    static std::string NormalizedRenamePrefix(std::string_view configured);

    static std::string StableMemberName(std::string_view original,
                                 const std::vector<std::string>& dictionary,
                                 std::uint64_t seed,
                                 std::set<std::string, std::less<>>& used);

    static bool IsSpecialMethod(std::string_view name);
};

} // namespace birch::guard::detail

