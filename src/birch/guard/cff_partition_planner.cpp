#include "cff_partition_planner.h"

#include "cfg_region_planner.h"
#include <algorithm>
#include <set>

namespace birch::guard::detail {

ConstantOutlineResult CffPartitionPlanner::OutlineConstants(const dex::DexFile& materialized,
    const GuardConfig& config, const CffPartitionRequired& request) {
    std::set<std::string, std::less<>> targets;
    for (const auto& failure : request.failures()) targets.insert(failure.method_key);
    return ConstantProgramOutliner::Apply(materialized, config, &targets);
}

CfgOutlineResult CffPartitionPlanner::Refine(const dex::DexFile& source,
    const GuardConfig& config, const CffPartitionRequired& request) {
    CfgRegionOutliner::Targets targets;
    for (const auto& failure : request.failures()) targets.emplace(failure.method_key, 0U);
    for (std::size_t c = 0; c < source.classes().size(); ++c) {
        const auto& data = source.class_data(c);
        for (const auto* methods : {&data.direct_methods, &data.virtual_methods}) {
            for (const auto& method : *methods) {
                const auto found = targets.find(source.method_key(method.method_idx));
                if (found == targets.end() || !method.code_off) continue;
                const auto units = dex::DecodeCodeItem(source, method.code_off).insns.size();
                // A subsequent failing helper gets a strictly smaller region
                // bound. No fixed source-size threshold can predict typed
                // dispatcher cost, so the exact next trial decides acceptance.
                if (units >= 2U * CfgRegionPlanner::kMinimumRegionUnits)
                    found->second = std::min(units / 2U, CfgRegionPlanner::kMaximumRegionUnits);
            }
        }
    }
    for (auto it = targets.begin(); it != targets.end();) {
        if (it->second == 0U) it = targets.erase(it);
        else ++it;
    }
    if (targets.empty()) throw std::length_error(std::string(request.what()) +
        "; no safe pre-materialization partition candidate");
    auto result = CfgRegionOutliner::Apply(source, config, &targets);
    if (result.bytes.empty()) throw std::length_error(std::string(request.what()) +
        "; CFG safety proof found no smaller callable regions");
    return result;
}

} // namespace birch::guard::detail
