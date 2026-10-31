#pragma once

#include "birch/dex/builder.h"
#include "birch/guard/model_lowering.h"

#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>

namespace birch::guard::detail {

struct EnumLoweringPlan {
    std::string owner;
    std::string method_name;
    std::uint32_t multiplier{};
    std::int32_t xor_mask{};
};


// Internal model-lowering component; helpers remain local to its translation unit.
class ModelEnumProtection final {
public:
    static void AddEnumProtocol(dex::ClassSpec& klass, const GuardConfig& config,
                         std::vector<EnumLoweringPlan>& plans);

    static std::vector<std::uint8_t> RewriteEnumCallsites(
        const dex::DexFile& source, const std::vector<EnumLoweringPlan>& plans,
        ModelLoweringResult& report);

};

} // namespace birch::guard::detail
