#include "birch/guard/scope.h"

#include "birch/utils/wildcard.h"

#include <algorithm>

namespace birch::guard {

bool MatchesAnyScopeRule(std::string_view value,
                         const std::vector<ScopeRule>& rules) noexcept {
    return std::any_of(rules.begin(), rules.end(), [&](const auto& rule) {
        return utils::WildcardMatch(value, rule.pattern);
    });
}

bool IsGuardGeneratedDescriptor(std::string_view descriptor) noexcept {
    return descriptor.starts_with("Lbirch/guard/") ||
           descriptor.starts_with("Lx/") ||
           descriptor.starts_with("Lx/fake/") ||
           descriptor.starts_with("Lx/birch/") ||
           descriptor.starts_with("Lx/obf/");
}

bool ScopeMatcher::IsKept(std::string_view descriptor) const noexcept {
    return MatchesAnyScopeRule(descriptor, config_->keep);
}

bool ScopeMatcher::IsProtected(std::string_view descriptor) const noexcept {
    return !IsKept(descriptor) &&
           (IsGuardGeneratedDescriptor(descriptor) ||
            MatchesAnyScopeRule(descriptor, config_->protect));
}

namespace {

template <typename Flag>
bool AllowsProtectFlag(std::string_view descriptor,
                       const ScopeConfig& config, Flag flag) noexcept {
    if (MatchesAnyScopeRule(descriptor, config.keep)) return false;
    bool matched = false;
    for (const auto& rule : config.protect) {
        if (!utils::WildcardMatch(descriptor, rule.pattern)) continue;
        matched = true;
        if (!flag(rule)) return false;
    }
    return matched;
}

} // namespace

bool ScopeMatcher::AllowsRenaming(std::string_view descriptor) const noexcept {
    if (IsGuardGeneratedDescriptor(descriptor) && !IsKept(descriptor)) return true;
    return AllowsProtectFlag(descriptor, *config_,
                             [](const ScopeRule& rule) { return rule.allow_renaming; });
}

bool ScopeMatcher::AllowsCodeTransforms(std::string_view descriptor) const noexcept {
    if (IsGuardGeneratedDescriptor(descriptor) && !IsKept(descriptor)) return true;
    return AllowsProtectFlag(descriptor, *config_,
                             [](const ScopeRule& rule) { return rule.allow_code_transforms; });
}

bool ScopeMatcher::IncludesMembers(std::string_view descriptor) const noexcept {
    if (IsGuardGeneratedDescriptor(descriptor) && !IsKept(descriptor)) return true;
    return AllowsProtectFlag(descriptor, *config_,
                             [](const ScopeRule& rule) { return rule.include_members; });
}

} // namespace birch::guard
