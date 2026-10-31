#pragma once

#include "birch/dex/partition.h"
#include "birch/guard/zip.h"

#include <map>
#include <set>
#include <string>
#include <string_view>

namespace birch::guard::detail {

// Preserve the input's loading contract; adding another ZIP entry does not
// install a legacy multidex loader. This is not an ART execution verifier.
class ApkDexLayout final {
public:
    explicit ApkDexLayout(const ZipArchive& source);

    [[nodiscard]] unsigned min_sdk() const noexcept { return min_sdk_; }
    bool MergeGeneratedDex(ZipArchive& archive, std::string_view generated,
                           const dex::IdLimits& limits) const;
    void Verify(const ZipArchive& output,
                const std::map<std::string, std::string, std::less<>>& classes) const;

private:
    unsigned min_sdk_{1U};
    bool single_input_{};
    std::set<std::string, std::less<>> primary_classes_;
    std::set<std::string, std::less<>> primary_types_;
};

} // namespace birch::guard::detail
