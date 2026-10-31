#pragma once

#include "birch/dex/builder.h"
#include "birch/guard/model_lowering.h"

#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>

namespace birch::guard::detail {

struct ArrayAccessorPlan {
    std::string owner;
    std::string field_name;
    std::string field_type;
    std::string element_type;
    std::string accessor_name;
    std::string split_init_name;
    std::array<std::string, 2U> split_field_names;
    bool virtualize{};
    bool split{};
};


// Internal model-lowering component; helpers remain local to its translation unit.
class ModelArrayProtection final {
public:
    static void AddArrayAccessors(dex::ClassSpec& klass, const GuardConfig& config,
                           std::vector<ArrayAccessorPlan>& plans);

    static std::vector<std::uint8_t> RewriteArrayCallsites(
        const dex::DexFile& source, const std::vector<ArrayAccessorPlan>& plans,
        std::size_t& rewritten_count, ModelLoweringResult& report);

};

} // namespace birch::guard::detail
