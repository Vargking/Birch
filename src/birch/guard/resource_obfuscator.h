#pragma once

#include "birch/guard/config.h"
#include "birch/guard/zip.h"
#include <map>
#include <string>
#include <vector>

namespace birch::guard::detail {

// Plan against original, unencrypted DEX strings, apply after code lowering.
// Resource IDs and entry layout are never rewritten.
class ResourceObfuscator final {
public:
    static ResourceObfuscator Plan(const ZipArchive& archive, const GuardConfig& config);
    void Apply(ZipArchive& archive) const;
    [[nodiscard]] const auto& paths() const noexcept { return paths_; }
    [[nodiscard]] const auto& names() const noexcept { return names_; }
    [[nodiscard]] const auto& warnings() const noexcept { return warnings_; }
    [[nodiscard]] const auto& mapping() const noexcept { return mapping_; }
private:
    std::map<std::string, std::string, std::less<>> paths_;
    std::map<std::string, std::string, std::less<>> names_;
    std::vector<std::string> warnings_;
    std::vector<std::string> mapping_;
};

} // namespace birch::guard::detail
