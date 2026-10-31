#pragma once

#include "birch/guard/config.h"

#include <string_view>
#include <vector>

namespace birch::guard {

[[nodiscard]] bool MatchesAnyScopeRule(std::string_view value,
                         const std::vector<ScopeRule>& rules) noexcept;

// Descriptors under these reserved namespaces are emitted by Birch itself.
// They are always transformation targets (unless an explicit keep rule
// matches), so helper/fake classes cannot accidentally bypass the pipeline.
[[nodiscard]] bool IsGuardGeneratedDescriptor(std::string_view descriptor) noexcept;

class ScopeMatcher final {
public:
    explicit ScopeMatcher(const ScopeConfig& config) : config_(&config) {}

    [[nodiscard]] bool IsKept(std::string_view descriptor) const noexcept;
    [[nodiscard]] bool IsProtected(std::string_view descriptor) const noexcept;
    // A matching keep rule always wins.  For overlapping protect rules the
    // most restrictive flag wins, so a single explicit false cannot be
    // bypassed by a broader wildcard rule.
    [[nodiscard]] bool AllowsRenaming(std::string_view descriptor) const noexcept;
    [[nodiscard]] bool AllowsCodeTransforms(std::string_view descriptor) const noexcept;
    [[nodiscard]] bool IncludesMembers(std::string_view descriptor) const noexcept;

private:
    const ScopeConfig* config_{};
};

} // namespace birch::guard
