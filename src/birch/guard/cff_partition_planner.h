#pragma once

#include "cff_code_budget.h"
#include "cfg_region_outliner.h"
#include "constant_program_outliner.h"

namespace birch::guard::detail {

// Uses exact post-materialization layout failures to partition the pristine
// (pre-materialization) CFG. The caller must rerun every pass on the new DEX;
// rejected trials must never contribute bytes, statistics or scratch layouts.
class CffPartitionPlanner final {
public:
    [[nodiscard]] static ConstantOutlineResult OutlineConstants(
        const dex::DexFile& materialized, const GuardConfig& config,
        const CffPartitionRequired& request);
    [[nodiscard]] static CfgOutlineResult Refine(
        const dex::DexFile& source, const GuardConfig& config,
        const CffPartitionRequired& request);
};

} // namespace birch::guard::detail
