#include "birch/guard/pass.h"

#include <algorithm>

namespace birch::guard {
namespace {

constexpr PassDescriptor kPasses[] = {
    {"rename.classes", PassCategory::Naming, false, true, 1.0},
    {"rename.methods", PassCategory::Naming, false, true, 1.0},
    {"rename.fields", PassCategory::Naming, false, true, 1.0},
    {"rename.parameters", PassCategory::Naming, false, false, 1.0},
    {"rename.packages", PassCategory::Naming, false, true, 1.0},
    {"rename.overload_induction", PassCategory::Naming, true, false, 0.5},
    {"structure.package_flattening", PassCategory::Structure, false, false, 0.5},
    {"structure.method_splitting", PassCategory::Structure, true, false, 0.5},
    {"structure.method_outlining", PassCategory::Structure, true, false, 0.5},
    {"structure.method_inlining", PassCategory::Structure, false, false, 0.5},
    {"structure.class_splitting", PassCategory::Structure, true, false, 0.5},
    {"structure.class_merging", PassCategory::Structure, false, false, 0.5},
    {"structure.interface_abstract_conversion", PassCategory::Structure, true, false, 0.5},
    {"structure.proxy_stubs", PassCategory::Structure, true, false, 0.5},
    {"reflection.indirect_targets", PassCategory::Structure, true, false, 0.5},
    {"loading.encrypted_paths", PassCategory::Data, true, false, 0.5},
    {"cfg.flattening", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.nested_flattening", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.multi_state_dispatch", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.bogus_edges", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.loop_state_machine", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.condition_expansion", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.conditional_nesting", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.table_dispatch", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.indirect_dispatch", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.mixed_ps_ss_if", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.exception_dispatch", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.callback_style", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.tail_recursion", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.dead_blocks", PassCategory::ControlFlow, true, false, 0.5},
    {"cfg.block_reordering", PassCategory::ControlFlow, false, false, 0.5},
    {"predicate.number_theory", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.polynomial", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.matrix", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.bitwise", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.floating_point", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.hash_collision", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.cross_process", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.cross_class_state", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.crypto", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.graph_problem", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.class_loading_state", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.reference_identity", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.history", PassCategory::OpaquePredicate, true, false, 0.5},
    {"predicate.overflow", PassCategory::OpaquePredicate, true, false, 0.5},
    {"data.string_encryption", PassCategory::Data, true, false, 0.5},
    {"data.string_splitting", PassCategory::Data, true, false, 0.5},
    {"data.constant_splitting", PassCategory::Data, true, false, 0.5},
    {"data.array_virtualization", PassCategory::Data, true, false, 0.5},
    {"data.array_splitting", PassCategory::Data, true, false, 0.5},
    {"data.reflection_string_encryption", PassCategory::Data, true, false, 0.5},
    {"data.enum_lowering", PassCategory::Data, true, false, 0.5},
    {"data.boolean_arithmetic", PassCategory::Data, true, false, 0.5},
    {"resources.file_rename", PassCategory::Data, false, false, 0.5},
    {"resources.name_rename", PassCategory::Data, false, false, 0.5},
    {"anti_analysis.debug_info_removal", PassCategory::AntiAnalysis, false, true, 1.0},
    {"anti_analysis.annotation_noise", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.path_explosion", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.ssa_pollution", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.constant_barriers", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.instruction_patterns", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.register_shape", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.legal_exception_layout", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.verifier_safe_overlap_substitute", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.decompiler_resilience", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.legal_overlapping_handlers", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.debug_local_noise", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.annotation_forgery", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.dataflow_pollution", PassCategory::AntiAnalysis, true, false, 0.5},
    {"anti_analysis.pattern_randomization", PassCategory::AntiAnalysis, true, false, 0.5},
    {"strength.per_method_randomization", PassCategory::Strength, false, true, 1.0},
    {"strength.build_parameter_randomization", PassCategory::Strength, false, true, 1.0},
    {"strength.anti_automation_profile", PassCategory::Strength, true, false, 0.5},
    {"strength.analysis_cost_budget", PassCategory::Strength, true, false, 0.5},
    {"fake.classes", PassCategory::Structure, true, false, 0.5},
    {"fake.calls", PassCategory::Structure, true, false, 0.5},
};

} // namespace

std::span<const PassDescriptor> PassRegistry() {
    return kPasses;
}

const PassDescriptor* FindPass(std::string_view id) {
    const auto found = std::find_if(std::begin(kPasses), std::end(kPasses),
                                    [&](const auto& pass) { return pass.id == id; });
    return found == std::end(kPasses) ? nullptr : found;
}

} // namespace birch::guard
