#pragma once

#include "birch/dex/dex_file.h"

#include <set>
#include <string>
#include <utility>

namespace birch::guard::detail {

// An APK-wide reservation set, including unresolved/array-only references.
// A generated definition must never capture an existing application type.
class ClassNamespace final {
public:
    using Names = std::set<std::string, std::less<>>;

    explicit ClassNamespace(Names reserved = {}) : names_(std::move(reserved)) {}
    void Reserve(const dex::DexFile& file);
    [[nodiscard]] const Names& names() const noexcept { return names_; }

private:
    Names names_;
};

} // namespace birch::guard::detail
