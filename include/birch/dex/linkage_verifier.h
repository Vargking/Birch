#pragma once

#include "birch/dex/linker.h"

#include <tuple>

namespace birch::dex {

struct LinkageRenames {
    std::map<std::string, std::string, std::less<>> classes;
    std::map<std::string, std::string, std::less<>> methods;
    std::map<std::string, std::string, std::less<>> fields;
};

struct LinkageReport {
    std::set<std::string, std::less<>> resolved;
    std::set<std::string, std::less<>> unresolved;
    std::set<std::string, std::less<>> runtime_unresolved;
    std::set<std::string, std::less<>> failures;
    std::set<std::string, std::less<>> relocated_classes;
    std::map<std::string, std::set<std::string, std::less<>>, std::less<>> bindings;
    std::set<std::string, std::less<>> application_classes;
    std::set<std::tuple<std::string, std::string, std::string>> inheritance;
};

class LinkageVerifier final {
public:
    [[nodiscard]] static LinkageReport Analyze(
        const std::vector<std::reference_wrapper<const DexFile>>& files,
        const DexFile* framework = nullptr, const LinkageRenames& renames = {});

    // Preserve pre-existing optional/API-level dependency failures, but never
    // accept a newly broken binding. Baseline symbols are translated using the
    // actual rename plan, not guessed by demangling output names.
    static void VerifyNoNewFailures(const LinkageReport& baseline,
        const std::vector<std::reference_wrapper<const DexFile>>& output,
        const DexFile* framework = nullptr);
};

} // namespace birch::dex
