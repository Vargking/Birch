#include "birch/dex/builder.h"
#include "birch/dex/cfg.h"
#include "birch/dex/code.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/ir.h"
#include "birch/dex/verifier.h"
#include "birch/guard/dex_lowering.h"
#include "birch/guard/config.h"
#include "birch/guard/model_lowering.h"

#include <algorithm>
#include <cassert>
#include <cstdint>

int main() {
    birch::dex::DexBuilder builder(38U);
    birch::dex::ClassSpec klass;
    klass.descriptor = "Lstress/Maximum;";
    birch::dex::MethodSpec method;
    method.name = "execute";
    method.return_type = "I";
    method.parameter_types = {"I"};
    method.access_flags = 0x0009U;
    method.body.registers_size = 4U;
    method.body.ins_size = 1U;
    method.body.code_units = {
        0x0012U,          // const/4 v0, #0
        0x0338U, 5U,      // if-eqz v3, case-two@6
        0x1012U,          // const/4 v0, #1
        0x0029U, 3U,      // goto/16 return@7
        0x2012U,          // case-two: const/4 v0, #2
        0x000fU,          // return v0
    };
    klass.direct_methods.push_back(std::move(method));
    builder.AddClass(std::move(klass));

    const auto source = birch::dex::DexFile::Parse(builder.Build());
    auto config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 777331,
      "scope": {"protect": [{"pattern": "Lstress/**;"}], "keep": []},
      "budget": {
        "max_code_units_per_method": 60000,
        "max_added_blocks_per_method": 1024,
        "max_added_try_regions_per_method": 256,
        "max_method_growth_ratio": 10000.0
      },
      "strength": {
        "per_method_strategy": true,
        "randomized_parameters": true,
        "reproducible_output": true,
        "anti_automation_profile": true,
        "target_analysis_cost_weeks": 0
      },
      "passes": {
        "cfg.flattening": {"enabled": true, "intensity": 1.0},
        "cfg.nested_flattening": {"enabled": true, "intensity": 1.0},
        "cfg.multi_state_dispatch": {"enabled": true, "intensity": 1.0},
        "cfg.mixed_ps_ss_if": {"enabled": true, "intensity": 1.0},
        "cfg.exception_dispatch": {"enabled": true, "intensity": 1.0},
        "cfg.loop_state_machine": {"enabled": true, "intensity": 1.0},
        "cfg.conditional_nesting": {"enabled": true, "intensity": 1.0},
        "cfg.condition_expansion": {"enabled": true, "intensity": 1.0},
        "cfg.bogus_edges": {"enabled": true, "intensity": 1.0},
        "anti_analysis.path_explosion": {"enabled": true, "intensity": 1.0},
        "anti_analysis.dataflow_pollution": {"enabled": true, "intensity": 1.0},
        "anti_analysis.register_shape": {"enabled": true, "intensity": 1.0},
        "anti_analysis.legal_overlapping_handlers": {"enabled": true, "intensity": 1.0},
        "data.constant_splitting": {"enabled": true, "intensity": 1.0},
        "anti_analysis.constant_barriers": {"enabled": true, "intensity": 1.0},
        "strength.anti_automation_profile": {"enabled": true, "intensity": 1.0}
      }
    })json");

    const auto modeled = birch::guard::DexModelLowering(config).Apply(source);
    const auto modeled_source = birch::dex::DexFile::Parse(modeled.bytes);
    const auto lowered = birch::guard::DexCodeLowering(config).Apply(
        modeled_source);
    assert(lowered.cfg_methods == 1U);
    assert(lowered.cfg_blocks_added >= 1024U);
    assert(lowered.pass_applications.at("strength.anti_automation_profile") >= 1024U);

    const auto output = birch::dex::DexFile::Parse(lowered.bytes);
    birch::dex::VerifyDexOrThrow(output, birch::dex::VerificationLevel::Full);
    const auto business_class = std::find_if(
        output.classes().begin(), output.classes().end(), [&](const auto& item) {
            return output.descriptor(item.class_idx) == "Lstress/Maximum;";
        });
    assert(business_class != output.classes().end());
    const auto business_index = static_cast<std::size_t>(
        std::distance(output.classes().begin(), business_class));
    const auto code = birch::dex::DecodeCodeItem(
        output,
        output.class_data(business_index).direct_methods.front().code_off);
    const auto contains = [&](std::uint8_t opcode) {
        return std::any_of(code.instructions.begin(), code.instructions.end(),
                           [&](const auto& instruction) {
            return instruction.opcode == opcode;
        });
    };
    assert(contains(0x2bU)); // packed-switch
    assert(contains(0x2cU)); // sparse-switch
    assert(contains(0x03U)); // explicit move/16 register-shape pollution
    assert(lowered.pass_applications.at(
               "anti_analysis.register_shape") > 0U);
    assert(contains(0x27U)); // catch/rethrow exception edge
    assert(contains(0xd7U)); // encrypted arithmetic data barrier
    assert(!code.tries.empty());
    assert(std::none_of(
        code.instructions.begin(), code.instructions.end(),
        [](const auto& instruction) {
            return instruction.kind != birch::dex::InstructionKind::Payload &&
                   instruction.opcode == 0x00U;
        }));
    const auto ir = birch::dex::BuildMethodIr(code);
    const auto original_code = birch::dex::DecodeCodeItem(
        modeled_source, modeled_source.class_data(business_index)
                            .direct_methods.front().code_off);
    assert(lowered.cfg_blocks_added == ir.blocks().size() -
           birch::dex::BuildMethodIr(original_code).blocks().size());
    assert(birch::dex::ControlFlowGraph(ir).Verify());
    assert(ir.blocks().size() > 700U);

    auto analysis_cost = config;
    analysis_cost.strength.anti_automation_profile = false;
    analysis_cost.strength.target_analysis_cost_weeks = 52U;
    analysis_cost.passes.at("strength.anti_automation_profile").enabled = false;
    analysis_cost.passes.at("strength.analysis_cost_budget").enabled = true;
    analysis_cost.passes.at("strength.analysis_cost_budget").intensity = 0.1;
    const auto analysis_cost_lowered = birch::guard::DexCodeLowering(
        analysis_cost).Apply(modeled_source);
    assert(analysis_cost_lowered.cfg_blocks_added >= 52U * 16U);
    birch::dex::VerifyDexOrThrow(
        birch::dex::DexFile::Parse(analysis_cost_lowered.bytes),
        birch::dex::VerificationLevel::Full);

    auto analysis_limited = config;
    analysis_limited.budget.max_analysis_blocks_per_method = 64U;
    bool rejected_analysis_overflow = false;
    try {
        (void)birch::guard::DexCodeLowering(analysis_limited).Apply(
            modeled_source);
    } catch (const std::runtime_error&) {
        rejected_analysis_overflow = true;
    }
    assert(rejected_analysis_overflow);
    return 0;
}
