#pragma once

#include "birch/dex/dex_file.h"

#include <functional>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace birch::dex {

enum class ResolutionStatus { Found, Missing, UnknownExternal };

struct MemberResolution {
    ResolutionStatus status{ResolutionStatus::Missing};
    std::string declaring_class;
    std::uint32_t access_flags{};
    bool virtual_method{};
    bool external{};
};

struct LinkClass {
    std::string superclass;
    std::vector<std::string> interfaces;
    std::uint32_t access_flags{};
    bool external{};
    std::map<std::string, MemberResolution, std::less<>> methods;
    std::map<std::string, MemberResolution, std::less<>> fields;
};

// One program-wide symbol table, shared by rename planning and linkage checks.
// A method_id/field_id owner is a symbolic lookup class, NOT necessarily the
// class declaring that member. Unknown dependencies are distinct from absence.
class DexLinker final {
public:
    explicit DexLinker(
        const std::vector<std::reference_wrapper<const DexFile>>& files,
        const DexFile* framework = nullptr);

    [[nodiscard]] const LinkClass* FindClass(std::string_view descriptor) const;
    [[nodiscard]] MemberResolution ResolveMethod(std::string_view owner,
        std::string_view name, std::string_view proto) const;
    [[nodiscard]] MemberResolution ResolveField(std::string_view owner,
        std::string_view name, std::string_view type) const;
    [[nodiscard]] bool IsSubclass(std::string_view child, std::string_view parent) const;

private:
    void AddFile(const DexFile& file, bool external);
    [[nodiscard]] MemberResolution Lookup(std::string_view owner,
        const std::string& key, bool field, bool inherit,
        std::set<std::string, std::less<>>& visiting) const;
    std::map<std::string, LinkClass, std::less<>> classes_;
};

} // namespace birch::dex
