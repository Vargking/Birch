#include "birch/guard/dex_lowering.h"
#include "strength_policy.h"
#include "prefix_assembler.h"
#include "control_flow_flattener.h"
#include "constant_program_outliner.h"
#include "linear_region_outliner.h"
#include "cfg_region_outliner.h"
#include "cff_partition_planner.h"

#include "birch/dex/code.h"
#include "birch/dex/ir.h"
#include "birch/dex/remap.h"
#include "birch/dex/type_analysis.h"
#include "birch/dex/verifier.h"
#include "birch/guard/scope.h"
#include "birch/guard/constant_runtime.h"
#include "birch/guard/opaque_runtime.h"
#include "birch/utils/hash.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <iterator>
#include <initializer_list>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>

namespace birch::guard {
using namespace detail;
namespace {

constexpr std::array<std::string_view, 26U> kControlFlowPasses{
    "cfg.flattening", "cfg.nested_flattening", "cfg.multi_state_dispatch",
    "cfg.bogus_edges", "cfg.loop_state_machine", "cfg.condition_expansion",
    "cfg.conditional_nesting", "cfg.table_dispatch", "cfg.indirect_dispatch",
    "cfg.mixed_ps_ss_if", "cfg.exception_dispatch", "cfg.callback_style",
    "cfg.dead_blocks", "cfg.block_reordering",
    "anti_analysis.pattern_randomization", "anti_analysis.instruction_patterns",
    "anti_analysis.dataflow_pollution",
    "anti_analysis.path_explosion",
    "anti_analysis.ssa_pollution",
    "anti_analysis.register_shape",
    "anti_analysis.legal_exception_layout",
    "anti_analysis.verifier_safe_overlap_substitute",
    "anti_analysis.decompiler_resilience",
    "anti_analysis.legal_overlapping_handlers",
    "strength.anti_automation_profile",
    "strength.analysis_cost_budget",
};

// These passes describe the final whole-method state machine.  All other
// control/data/opaque passes are materialized first, then this set is run in
// a second lowering phase over the resulting CFG so their blocks become
// dispatcher cases instead of a linear prologue.
constexpr std::array<std::string_view, 14U> kWholeMethodDispatcherPasses{
    "cfg.flattening",
    "cfg.nested_flattening",
    "cfg.multi_state_dispatch",
    "cfg.bogus_edges",
    "cfg.loop_state_machine",
    "cfg.condition_expansion",
    "cfg.conditional_nesting",
    "cfg.table_dispatch",
    "cfg.indirect_dispatch",
    "cfg.mixed_ps_ss_if",
    "cfg.callback_style",
    "cfg.dead_blocks",
    "cfg.block_reordering",
    "anti_analysis.path_explosion",
};

enum class ConstantOperation : std::uint8_t {
    Xor16,
    Add16,
};

struct ConstantStep {
    ConstantOperation operation{};
    std::int16_t literal{};
};

std::optional<std::pair<std::uint16_t, std::int32_t>> DecodeIntConstant(
    const dex::DecodedInstruction& instruction) {
    const auto first = instruction.code_units.front();
    if (instruction.opcode == 0x12U) {
        auto literal = static_cast<std::int32_t>((first >> 12U) & 0x0fU);
        if ((literal & 0x08) != 0) literal |= ~0x0f;
        return std::pair(static_cast<std::uint16_t>((first >> 8U) & 0x0fU),
                         literal);
    }
    if (instruction.opcode == 0x13U) {
        return std::pair(static_cast<std::uint16_t>(first >> 8U),
                         static_cast<std::int32_t>(static_cast<std::int16_t>(
                             instruction.code_units.at(1U))));
    }
    if (instruction.opcode == 0x14U) {
        const auto bits = static_cast<std::uint32_t>(
            instruction.code_units.at(1U)) |
            static_cast<std::uint32_t>(instruction.code_units.at(2U)) << 16U;
        return std::pair(static_cast<std::uint16_t>(first >> 8U),
                         static_cast<std::int32_t>(bits));
    }
    if (instruction.opcode == 0x15U) {
        const auto bits = static_cast<std::uint32_t>(
            instruction.code_units.at(1U)) << 16U;
        return std::pair(static_cast<std::uint16_t>(first >> 8U),
                         static_cast<std::int32_t>(bits));
    }
    return std::nullopt;
}

std::vector<std::uint16_t> EncodeSplitConstant(
    std::uint16_t destination, std::int32_t value,
    const std::vector<ConstantStep>& steps,
    std::optional<std::uint16_t> runtime_barrier,
    dex::ConstantUseType use_type,
    std::optional<std::uint16_t> reference_type,
    bool restore_verifier_null) {
    if (destination > 0x0fU || steps.empty()) return {};
    auto initial = static_cast<std::uint32_t>(value);
    for (auto iterator = steps.rbegin(); iterator != steps.rend(); ++iterator) {
        const auto literal = static_cast<std::uint32_t>(
            static_cast<std::int32_t>(iterator->literal));
        if (iterator->operation == ConstantOperation::Xor16) {
            initial ^= literal;
        } else {
            initial -= literal;
        }
    }
    std::vector<std::uint16_t> result{
        static_cast<std::uint16_t>(0x14U | (destination << 8U)),
        static_cast<std::uint16_t>(initial),
        static_cast<std::uint16_t>(initial >> 16U),
    };
    for (const auto& step : steps) {
        const auto opcode = step.operation == ConstantOperation::Xor16 ?
            0xd7U : 0xd0U;
        result.push_back(static_cast<std::uint16_t>(
            opcode | (destination << 8U) | (destination << 12U)));
        result.push_back(static_cast<std::uint16_t>(step.literal));
    }
    if (runtime_barrier.has_value()) {
        result.insert(result.end(), {
            0x1071U, *runtime_barrier, destination,
            static_cast<std::uint16_t>(
                (use_type == dex::ConstantUseType::Reference ? 0x0cU : 0x0aU) |
                (destination << 8U)),
        });
        if (use_type == dex::ConstantUseType::Reference) {
            if (reference_type.has_value()) {
                result.insert(result.end(), {
                    static_cast<std::uint16_t>(
                        0x1fU | (destination << 8U)),
                    *reference_type,
                });
            } else if (restore_verifier_null) {
                // A runtime helper has the declared return type Object. When
                // one source null feeds unrelated verifier types, no single
                // check-cast can represent every use. Retain the full runtime
                // barrier and re-establish DEX's polymorphic zero/null type.
                result.push_back(static_cast<std::uint16_t>(
                    0x12U | (destination << 8U)));
            }
        }
    }
    return result;
}

bool SelectInstructionPass(const PassConfig& pass, std::uint64_t global_seed,
                           std::string_view method_key,
                           std::uint32_t instruction_offset,
                           std::uint64_t salt, std::uint32_t applications) {
    if (!pass.enabled || (pass.max_applications_per_method.has_value() &&
                          applications >= *pass.max_applications_per_method)) {
        return false;
    }
    const auto state = utils::StableHash64(
        std::string(method_key) + ':' + std::to_string(instruction_offset),
        pass.seed.value_or(global_seed) ^ salt);
    const auto sample = static_cast<double>(state >> 11U) /
                        static_cast<double>(std::uint64_t{1U} << 53U);
    return sample <= pass.intensity;
}

std::int16_t NonZeroLiteral(std::uint64_t& state) {
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    auto literal = static_cast<std::int16_t>(state);
    if (literal == 0) literal = static_cast<std::int16_t>(0x5a5b);
    return literal;
}

std::vector<dex::CodePrefix> BuildPrefixes(const dex::DexFile& dex_file,
                                           const GuardConfig& config,
                                           std::size_t& cfg_changed,
                                           std::size_t& flattened_methods,
                                           std::size_t& cfg_blocks_added,
                                           std::size_t& data_changed,
                                           std::size_t& constants_rewritten,
                                           std::map<std::string, std::size_t,
                                                     std::less<>>&
                                               pass_applications,
                                           const MaterializedRegisterLayouts*
                                               materialized_layouts = nullptr,
                                           MaterializedRegisterLayouts*
                                               produced_layouts = nullptr) {
    std::vector<dex::CodePrefix> prefixes;
    std::vector<CffPartitionFailure> partition_failures;
    cfg_changed = 0U;
    flattened_methods = 0U;
    cfg_blocks_added = 0U;
    data_changed = 0U;
    constants_rewritten = 0U;
    for (const auto id : kControlFlowPasses) {
        pass_applications.try_emplace(std::string(id), 0U);
    }
    for (const auto id : kRuntimeOpaquePasses) {
        pass_applications.try_emplace(std::string(id), 0U);
    }
    for (const auto id : {"data.constant_splitting",
                          "data.boolean_arithmetic",
                          "anti_analysis.constant_barriers",
                          "anti_analysis.instruction_patterns"}) {
        pass_applications.try_emplace(id, 0U);
    }
    const ScopeMatcher scope(config.scope);
    std::array<std::optional<std::uint16_t>, kRuntimeOpaquePasses.size()>
        opaque_method_indices;
    std::set<std::string, std::less<>> opaque_helper_owners;
    std::set<std::string, std::less<>> exception_helper_owners;
    std::set<std::string, std::less<>> constant_helper_owners;
    std::optional<std::uint16_t> exception_helper_method;
    std::optional<std::uint16_t> constant_helper_method;
    std::optional<std::uint16_t> float_constant_helper_method;
    std::optional<std::uint16_t> null_constant_helper_method;
    std::array<std::string, kRuntimeOpaquePasses.size()> opaque_method_names;
    for (std::size_t strategy = 0U; strategy < opaque_method_names.size();
         ++strategy) {
        opaque_method_names[strategy] =
            RuntimeOpaqueMethodName(config.seed, strategy);
    }
    const std::array<std::string, kRuntimeExceptionStateFields>
        exception_field_names{
            RuntimeExceptionFieldName(config.seed, 0U),
            RuntimeExceptionFieldName(config.seed, 1U),
        };
    const std::array<std::string, kRuntimeConstantStateFields>
        constant_field_names{
            RuntimeConstantFieldName(config.seed, 0U),
            RuntimeConstantFieldName(config.seed, 1U),
        };
    for (std::size_t class_index = 0U;
         class_index < dex_file.classes().size(); ++class_index) {
        const auto& data = dex_file.class_data(class_index);
        std::array<bool, kRuntimeExceptionStateFields> found_fields{};
        std::array<bool, kRuntimeConstantStateFields> found_constant_fields{};
        for (const auto& encoded_field : data.static_fields) {
            const auto& field = dex_file.fields().at(encoded_field.field_idx);
            if (dex_file.descriptor(field.type_idx) != "I") continue;
            const auto name = dex_file.string(field.name_idx);
            for (std::size_t slot = 0U; slot < found_fields.size(); ++slot) {
                found_fields[slot] = found_fields[slot] ||
                                     name == exception_field_names[slot];
            }
            for (std::size_t slot = 0U; slot < found_constant_fields.size();
                 ++slot) {
                found_constant_fields[slot] = found_constant_fields[slot] ||
                                              name == constant_field_names[slot];
            }
        }
        if (std::all_of(found_fields.begin(), found_fields.end(),
                        [](const auto found) { return found; })) {
            exception_helper_owners.insert(dex_file.descriptor(
                dex_file.classes()[class_index].class_idx));
        }
        if (std::all_of(found_constant_fields.begin(),
                        found_constant_fields.end(),
                        [](const auto found) { return found; })) {
            constant_helper_owners.insert(dex_file.descriptor(
                dex_file.classes()[class_index].class_idx));
        }
    }
    const auto exception_method_name = RuntimeExceptionMethodName(config.seed);
    const auto constant_method_name = RuntimeConstantMethodName(config.seed);
    const auto float_constant_method_name =
        RuntimeFloatConstantMethodName(config.seed);
    const auto null_constant_method_name =
        RuntimeNullConstantMethodName(config.seed);
    for (std::uint32_t method_index = 0U;
         method_index < dex_file.methods().size(); ++method_index) {
        const auto& method = dex_file.methods()[method_index];
        const auto owner = dex_file.descriptor(method.class_idx);
        const auto proto = dex_file.proto_key(method.proto_idx);
        const auto name = dex_file.string(method.name_idx);
        if (proto == "(I)I" && constant_helper_owners.contains(owner) &&
            name == constant_method_name) {
            if (method_index > std::numeric_limits<std::uint16_t>::max()) {
                throw std::length_error(
                    "constant runtime helper method index exceeds uint16");
            }
            if (constant_helper_method.has_value()) {
                throw std::runtime_error(
                    "multiple constant runtime helpers found in one DEX");
            }
            constant_helper_method = static_cast<std::uint16_t>(method_index);
        }
        if (proto == "(I)F" && constant_helper_owners.contains(owner) &&
            name == float_constant_method_name) {
            if (method_index > std::numeric_limits<std::uint16_t>::max()) {
                throw std::length_error(
                    "float constant helper method index exceeds uint16");
            }
            if (float_constant_helper_method.has_value()) {
                throw std::runtime_error(
                    "multiple float constant helpers found in one DEX");
            }
            float_constant_helper_method =
                static_cast<std::uint16_t>(method_index);
        }
        if (proto == "(I)Ljava/lang/Object;" &&
            constant_helper_owners.contains(owner) &&
            name == null_constant_method_name) {
            if (method_index > std::numeric_limits<std::uint16_t>::max()) {
                throw std::length_error(
                    "null constant helper method index exceeds uint16");
            }
            if (null_constant_helper_method.has_value()) {
                throw std::runtime_error(
                    "multiple null constant helpers found in one DEX");
            }
            null_constant_helper_method =
                static_cast<std::uint16_t>(method_index);
        }
        if (proto != "()I") continue;
        if (exception_helper_owners.contains(owner) &&
            name == exception_method_name) {
            if (method_index > std::numeric_limits<std::uint16_t>::max()) {
                throw std::length_error(
                    "exception runtime helper method index exceeds uint16");
            }
            if (exception_helper_method.has_value()) {
                throw std::runtime_error(
                    "multiple exception runtime helpers found in one DEX");
            }
            exception_helper_method = static_cast<std::uint16_t>(method_index);
        }
        for (std::size_t strategy = 0U;
             strategy < kRuntimeOpaquePasses.size(); ++strategy) {
            if (name == opaque_method_names[strategy]) {
                if (method_index > std::numeric_limits<std::uint16_t>::max()) {
                    throw std::length_error(
                        "opaque runtime helper method index exceeds uint16");
                }
                opaque_method_indices[strategy] =
                    static_cast<std::uint16_t>(method_index);
                opaque_helper_owners.insert(owner);
            }
        }
    }
    // DexCodeLowering is also a public low-level entry point. Runtime predicate
    // passes remain at zero applications when model lowering did not inject
    // their helper; they are never substituted with a weaker local template.
    for (std::size_t class_index = 0U; class_index < dex_file.classes().size();
         ++class_index) {
        const auto owner = dex_file.descriptor(dex_file.classes()[class_index].class_idx);
        const auto opaque_helper = opaque_helper_owners.contains(owner);
        const auto exception_helper = exception_helper_owners.contains(owner);
        const auto constant_helper = constant_helper_owners.contains(owner);
        const auto core_runtime_helper =
            opaque_helper || exception_helper || constant_helper;
        if (!scope.IsProtected(owner) ||
            !scope.AllowsCodeTransforms(owner)) continue;
        const auto& data = dex_file.class_data(class_index);
        const auto collect = [&](const std::vector<dex::DexEncodedMethod>& methods) {
            for (const auto& encoded : methods) {
                if (encoded.code_off == 0U) continue;
                const auto& method = dex_file.methods().at(encoded.method_idx);
                const auto code = dex::DecodeCodeItem(dex_file, encoded.code_off);
                const auto source_ir = dex::BuildMethodIr(code);
                const auto source_blocks = source_ir.blocks().size();
                const auto source_has_back_edge = std::any_of(
                    source_ir.blocks().begin(), source_ir.blocks().end(),
                    [&](const auto& block) {
                        return std::any_of(
                            block.successors.begin(), block.successors.end(),
                            [&](const auto& edge) {
                                return edge.kind != dex::IrEdgeKind::Exception &&
                                       edge.target <= block.id;
                            });
                    });
                const auto source_has_condition = std::any_of(
                    code.instructions.begin(), code.instructions.end(),
                    [](const auto& instruction) {
                        return instruction.kind ==
                            dex::InstructionKind::ConditionalBranch;
                    });
                if (source_blocks >
                    config.budget.max_analysis_blocks_per_method) {
                    throw std::runtime_error(
                        "source CFG exceeds max_analysis_blocks_per_method for " +
                        owner + dex_file.method_key(encoded.method_idx));
                }
                const auto method_key = owner +
                    dex_file.method_key(encoded.method_idx);
                dex::MethodTypeAnalysis type_analysis;
                const bool needs_type_analysis =
                    config.passes.at("data.constant_splitting").enabled ||
                    config.passes.at("data.boolean_arithmetic").enabled ||
                    config.passes.at("anti_analysis.constant_barriers").enabled ||
                    config.passes.at("anti_analysis.instruction_patterns").enabled;
                if (needs_type_analysis) {
                    type_analysis = dex::AnalyzeMethodTypes(
                        dex_file, encoded, code);
                    if (!type_analysis.issues.empty()) {
                        throw std::runtime_error(
                            "register type analysis rejected " + method_key +
                            " at code-unit 0x" +
                            [&]() {
                                std::ostringstream stream;
                                stream << std::hex
                                       << type_analysis.issues.front()
                                              .instruction_offset;
                                return stream.str();
                            }() + ": " +
                            type_analysis.issues.front().message);
                    }
                }
                std::set<std::string_view> selected_control;
                for (std::size_t pass_index = 0U;
                     pass_index < kControlFlowPasses.size(); ++pass_index) {
                    const auto id = kControlFlowPasses[pass_index];
                    const auto& pass = config.passes.at(std::string(id));
                    if (!pass.enabled) continue;
                    const auto selection = utils::StableHash64(
                        method_key,
                        pass.seed.value_or(config.seed) ^ pass_index);
                    const auto sample = static_cast<double>(selection >> 11U) /
                        static_cast<double>(std::uint64_t{1} << 53U);
                    if (sample <= pass.intensity) selected_control.insert(id);
                }
                // cfg.flattening is a structural guarantee, not a sampling
                // hint.  Once enabled every eligible method must enter the
                // dispatcher.  The intensity still controls how many guards,
                // dead states, and repetitions are emitted below.
                const bool base_flattening_selected =
                    config.passes.at("cfg.flattening").enabled;
                if (base_flattening_selected) {
                    // A single sparse switch is only a dispatcher-shaped
                    // linear layout.  Enable every configured dispatcher
                    // layer for a real mixed packed/sparse CFF graph.
                    for (const auto id : {"cfg.nested_flattening",
                                          "cfg.multi_state_dispatch",
                                          "cfg.table_dispatch",
                                          "cfg.indirect_dispatch",
                                          "cfg.mixed_ps_ss_if",
                                          "cfg.exception_dispatch",
                                          "cfg.callback_style",
                                          "cfg.condition_expansion",
                                          "cfg.conditional_nesting",
                                          "cfg.bogus_edges",
                                          "cfg.dead_blocks",
                                          "cfg.block_reordering",
                                          "anti_analysis.path_explosion"}) {
                        const auto& companion = config.passes.at(id);
                        if (companion.enabled) selected_control.insert(id);
                    }
                }
                const bool nested_dispatch_selected =
                    selected_control.contains("cfg.nested_flattening");
                const bool multi_state_dispatch_selected =
                    selected_control.contains("cfg.multi_state_dispatch");
                const bool table_dispatch_selected =
                    selected_control.contains("cfg.table_dispatch");
                const bool indirect_dispatch_selected =
                    selected_control.contains("cfg.indirect_dispatch");
                const bool explicit_mixed_dispatch_selected =
                    selected_control.contains("cfg.mixed_ps_ss_if");
                const bool callback_style_selected =
                    source_blocks >= 2U &&
                    selected_control.contains("cfg.callback_style") &&
                    exception_helper_method.has_value() &&
                    !core_runtime_helper;
                const bool mixed_dispatch_selected =
                    explicit_mixed_dispatch_selected ||
                    (table_dispatch_selected && indirect_dispatch_selected);
                const bool condition_expansion_selected =
                    source_has_condition &&
                    selected_control.contains("cfg.condition_expansion");
                const bool conditional_nesting_selected =
                    source_has_condition &&
                    selected_control.contains("cfg.conditional_nesting");
                const bool bogus_edges_selected =
                    source_has_condition &&
                    selected_control.contains("cfg.bogus_edges");
                const bool dead_blocks_selected =
                    selected_control.contains("cfg.dead_blocks");
                const bool path_explosion_selected =
                    source_has_condition &&
                    selected_control.contains("anti_analysis.path_explosion");
                const bool loop_state_machine_selected =
                    source_has_back_edge &&
                    selected_control.contains("cfg.loop_state_machine");
                const bool flattening_selected = base_flattening_selected ||
                    nested_dispatch_selected || multi_state_dispatch_selected ||
                    table_dispatch_selected || indirect_dispatch_selected ||
                    mixed_dispatch_selected || callback_style_selected ||
                    condition_expansion_selected ||
                    conditional_nesting_selected || bogus_edges_selected ||
                    dead_blocks_selected || path_explosion_selected ||
                    loop_state_machine_selected;
                const bool layered_dispatch_selected =
                    nested_dispatch_selected || multi_state_dispatch_selected ||
                    mixed_dispatch_selected || callback_style_selected;
                const auto dispatcher_encoding = mixed_dispatch_selected ?
                    DispatcherEncoding::Mixed :
                    table_dispatch_selected && !indirect_dispatch_selected ?
                        DispatcherEncoding::Packed :
                        DispatcherEncoding::Sparse;
                std::optional<std::uint16_t> predicate_register;
                const auto input_base = static_cast<std::uint32_t>(code.registers_size) -
                                        code.ins_size;
                // Never borrow v0/v1 from the business method. Once the
                // materialized prefix is flattened, every generated block is
                // independently verifier-reachable from the dispatcher.
                const auto can_reserve_scratch =
                    code.registers_size <= 253U &&
                    code.registers_size + 2U <=
                        config.budget.max_registers_per_method;
                std::optional<std::uint16_t> scratch_register =
                    can_reserve_scratch ?
                        std::optional<std::uint16_t>{code.registers_size} :
                        std::nullopt;
                std::optional<std::uint16_t> second_scratch =
                    can_reserve_scratch ?
                        std::optional<std::uint16_t>{static_cast<std::uint16_t>(
                            code.registers_size + 1U)} : std::nullopt;
                constexpr std::uint32_t kStatic = 0x0008U;
                if ((encoded.access_flags & kStatic) == 0U && code.ins_size != 0U &&
                    input_base <= 0xffU) {
                    predicate_register = static_cast<std::uint16_t>(input_base);
                } else if ((encoded.access_flags & kStatic) != 0U) {
                    std::uint32_t word = 0U;
                    for (const auto type_idx : dex_file.type_list(
                             dex_file.protos().at(method.proto_idx).parameters_off)) {
                        const auto descriptor = dex_file.descriptor(type_idx);
                        const auto width = descriptor == "J" || descriptor == "D" ? 2U : 1U;
                        const auto usable = descriptor != "J" && descriptor != "D" &&
                                            descriptor != "F" && descriptor != "V";
                        if (usable && input_base + word <= 0xffU) {
                            predicate_register = static_cast<std::uint16_t>(input_base + word);
                            break;
                        }
                        word += width;
                    }
                }
                const auto max_growth_units = StrengthPolicy::GrowthLimit(
                    code.insns.size(), config.budget.max_method_growth_ratio - 1.0);
                const auto max_by_code_units = config.budget.max_code_units_per_method >
                    code.insns.size() ?
                    config.budget.max_code_units_per_method - code.insns.size() : 0U;
                const auto allowed = static_cast<std::size_t>(
                    std::min<std::uint64_t>(max_growth_units, max_by_code_units));
                const auto analysis_headroom =
                    config.budget.max_analysis_blocks_per_method -
                    source_blocks;
                PrefixAssembler assembler(
                    allowed, config.budget.max_added_try_regions_per_method,
                    std::min<std::size_t>(
                        config.budget.max_added_blocks_per_method,
                        analysis_headroom));
                bool method_cfg_changed = false;
                bool method_data_changed = false;
                bool method_uses_constant_barrier = false;
                const bool dispatcher_materialization =
                    materialized_layouts != nullptr || produced_layouts != nullptr;
                std::map<std::string_view, std::uint32_t> applications;
                const auto& constant_split =
                    config.passes.at("data.constant_splitting");
                const auto& boolean_arithmetic =
                    config.passes.at("data.boolean_arithmetic");
                const auto& constant_barriers =
                    config.passes.at("anti_analysis.constant_barriers");
                const auto &instruction_patterns =
                    config.passes.at("anti_analysis.instruction_patterns");
                for (const auto &instruction : code.instructions) {
                  if (instruction.kind != dex::InstructionKind::Payload &&
                      instruction.opcode == 0x00U && instruction.width == 1U) {
                    // Do not leave canonical padding/nop instructions in
                    // either a complete replacement or its safe fallback.
                    // A payload-alignment nop cannot become goto +1: that
                    // would make executable control flow target payload
                    // data. Use const/4 instead of move-to-self because ART
                    // verifies dead alignment islands with undefined input
                    // registers. The one-unit definition preserves parity.
                    const auto next = std::find_if(
                        code.instructions.begin(), code.instructions.end(),
                        [&](const auto &candidate) {
                          return candidate.offset ==
                                 instruction.offset + instruction.width;
                        });
                    std::vector<std::uint16_t> replacement{0x0128U};
                    if (next != code.instructions.end() &&
                        next->kind == dex::InstructionKind::Payload) {
                      if (code.registers_size == 0U) {
                        throw std::logic_error(
                            "payload alignment requires a register for "
                            "non-nop substitution in " +
                            method_key);
                      }
                      replacement = {0x0012U}; // const/4 v0, #0
                    }
                    if (assembler.ReplaceInstruction(instruction.offset,
                                                     instruction.width,
                                                     std::move(replacement))) {
                      method_cfg_changed = true;
                    }
                    continue;
                  }
                  const auto decoded_constant = DecodeIntConstant(instruction);
                  if (!decoded_constant.has_value() ||
                      decoded_constant->first > 0x0fU) {
                    continue;
                  }
                  if (type_analysis.polymorphic_zero_constants.contains(
                          instruction.offset)) {
                    // A zero literal can legally flow to both a primitive
                    // consumer and a reference/null consumer. Replacing it
                    // with one typed helper would change verifier state on
                    // one branch, so preserve the original polymorphic const.
                    continue;
                  }
                  const auto classified =
                      type_analysis.constant_uses.find(instruction.offset);
                  const auto constant_type =
                      classified == type_analysis.constant_uses.end() ||
                              classified->second ==
                                  dex::ConstantUseType::Unconstrained
                          ? dex::ConstantUseType::Int32
                          : classified->second;
                  if (constant_type == dex::ConstantUseType::Conflict) {
                    throw std::runtime_error(
                        "constant has incompatible verifier uses in " +
                        method_key + " at code-unit " +
                        std::to_string(instruction.offset));
                  }
                  std::vector<ConstantStep> steps;
                  auto state = utils::StableHash64(
                      method_key + ':' + std::to_string(instruction.offset),
                      config.seed);
                  const auto split_selected =
                      !constant_helper && constant_helper_method.has_value() &&
                      SelectInstructionPass(
                          constant_split, config.seed, method_key,
                          instruction.offset, 0x434f4e53U,
                          applications["data.constant_splitting"]);
                  if (split_selected) {
                    const auto rounds =
                        2U + static_cast<std::uint32_t>(
                                 std::ceil(constant_split.intensity * 14.0));
                    for (std::uint32_t round = 0U; round < rounds; ++round) {
                      steps.push_back({(round & 1U) == 0U
                                           ? ConstantOperation::Xor16
                                           : ConstantOperation::Add16,
                                       NonZeroLiteral(state)});
                    }
                  }
                  const auto boolean_selected =
                      !constant_helper && constant_helper_method.has_value() &&
                      constant_type == dex::ConstantUseType::Int32 &&
                      (decoded_constant->second == 0 ||
                       decoded_constant->second == 1) &&
                      SelectInstructionPass(
                          boolean_arithmetic, config.seed, method_key,
                          instruction.offset, 0x424f4f4cU,
                          applications["data.boolean_arithmetic"]);
                  if (boolean_selected) {
                    const auto rounds =
                        2U + static_cast<std::uint32_t>(
                                 std::ceil(boolean_arithmetic.intensity * 6.0));
                    for (std::uint32_t round = 0U; round < rounds; ++round) {
                      steps.push_back({(round & 1U) == 0U
                                           ? ConstantOperation::Add16
                                           : ConstantOperation::Xor16,
                                       NonZeroLiteral(state)});
                    }
                  }
                  const auto barrier_selected =
                      !constant_helper && constant_helper_method.has_value() &&
                      SelectInstructionPass(
                          constant_barriers, config.seed, method_key,
                          instruction.offset, 0x42415252U,
                          applications["anti_analysis.constant_barriers"]);
                  if (barrier_selected) {
                    const auto rounds =
                        4U + static_cast<std::uint32_t>(
                                 std::ceil(constant_barriers.intensity * 12.0));
                    for (std::uint32_t round = 0U; round < rounds; ++round) {
                      steps.push_back({(round & 1U) == 0U
                                           ? ConstantOperation::Xor16
                                           : ConstantOperation::Add16,
                                       NonZeroLiteral(state)});
                    }
                  }
                  const auto patterns_selected = SelectInstructionPass(
                      instruction_patterns, config.seed, method_key,
                      instruction.offset, 0x49504154U,
                      applications["anti_analysis.instruction_patterns"]);
                  if (patterns_selected) {
                    const auto rounds =
                        3U + static_cast<std::uint32_t>(std::ceil(
                                 instruction_patterns.intensity * 13.0));
                    for (std::uint32_t round = 0U; round < rounds; ++round) {
                      state ^= state << 13U;
                      state ^= state >> 7U;
                      state ^= state << 17U;
                      steps.push_back({(state & 1U) == 0U
                                           ? ConstantOperation::Xor16
                                           : ConstantOperation::Add16,
                                       NonZeroLiteral(state)});
                    }
                  }
                  if (steps.empty())
                    continue;
                  std::optional<std::uint16_t> runtime_barrier;
                  std::optional<std::uint16_t> reference_type;
                  bool restore_verifier_null = false;
                  switch (constant_type) {
                  case dex::ConstantUseType::Float32:
                    runtime_barrier = float_constant_helper_method;
                    break;
                  case dex::ConstantUseType::Reference:
                    if (decoded_constant->second != 0) {
                      throw std::runtime_error(
                          "non-zero reference constant in " + method_key);
                    }
                    runtime_barrier = null_constant_helper_method;
                    if (const auto descriptors =
                            type_analysis.constant_reference_descriptors.find(
                                instruction.offset);
                        descriptors !=
                            type_analysis.constant_reference_descriptors.end()) {
                      std::vector<std::string_view> precise;
                      for (const auto& descriptor : descriptors->second) {
                        if (descriptor != "Ljava/lang/Object;") {
                          precise.push_back(descriptor);
                        }
                      }
                      std::sort(precise.begin(), precise.end());
                      precise.erase(std::unique(precise.begin(), precise.end()),
                                    precise.end());
                      if (precise.size() == 1U) {
                        for (std::size_t type_index = 0U;
                             type_index < dex_file.types().size(); ++type_index) {
                          if (dex_file.descriptor(
                                  static_cast<std::uint32_t>(type_index)) ==
                              precise.front()) {
                            if (type_index >
                                std::numeric_limits<std::uint16_t>::max()) {
                              throw std::length_error(
                                  "reference constant cast type exceeds uint16");
                            }
                            reference_type =
                                static_cast<std::uint16_t>(type_index);
                            break;
                          }
                        }
                        if (!reference_type.has_value()) {
                          throw std::runtime_error(
                              "reference constant cast type is absent from DEX: " +
                              std::string(precise.front()));
                        }
                      } else if (precise.size() > 1U) {
                        restore_verifier_null = true;
                      }
                    }
                    break;
                  case dex::ConstantUseType::Int32:
                  case dex::ConstantUseType::Unconstrained:
                    runtime_barrier = constant_helper_method;
                    break;
                  case dex::ConstantUseType::Conflict:
                    break;
                  }
                  if (!runtime_barrier.has_value() &&
                      constant_type != dex::ConstantUseType::Int32 &&
                      constant_type != dex::ConstantUseType::Unconstrained) {
                    throw std::runtime_error(
                        "typed constant runtime helper is missing for " +
                        method_key);
                  }
                  auto replacement = EncodeSplitConstant(
                      decoded_constant->first, decoded_constant->second, steps,
                      runtime_barrier, constant_type, reference_type,
                      restore_verifier_null);
                  if (!assembler.ReplaceInstruction(instruction.offset,
                                                    instruction.width,
                                                    std::move(replacement))) {
                    continue;
                  }
                  if (split_selected) {
                    ++applications["data.constant_splitting"];
                    ++pass_applications["data.constant_splitting"];
                  }
                  method_uses_constant_barrier = method_uses_constant_barrier ||
                                                 runtime_barrier.has_value();
                  if (boolean_selected) {
                    ++applications["data.boolean_arithmetic"];
                    ++pass_applications["data.boolean_arithmetic"];
                  }
                  if (barrier_selected) {
                    ++applications["anti_analysis.constant_barriers"];
                    ++pass_applications["anti_analysis.constant_barriers"];
                  }
                  if (patterns_selected) {
                    ++applications["anti_analysis.instruction_patterns"];
                    ++pass_applications["anti_analysis.instruction_patterns"];
                  }
                  ++constants_rewritten;
                  method_data_changed = true;
                }
                for (std::size_t pass_index = 0U; pass_index < kControlFlowPasses.size();
                     ++pass_index) {
                    const auto id = kControlFlowPasses[pass_index];
                    const auto& pass = config.passes.at(
                        std::string(id));
                    if (!selected_control.contains(id)) continue;
                    auto state = utils::StableHash64(
                        owner + dex_file.method_key(encoded.method_idx),
                        pass.seed.value_or(config.seed) ^ pass_index);
                    auto repetitions = 1U +
                        static_cast<std::uint32_t>(pass.intensity * 3.0);
                    if (dispatcher_materialization) {
                        // Every enabled strategy remains present, but the
                        // complete CFF stage supplies the 256-block floor.
                        // Repeating each identical materialization four times
                        // only multiplies ART compiler work and method size.
                        repetitions = 1U;
                    }
                    if (pass.max_applications_per_method.has_value()) {
                        repetitions = std::min(repetitions,
                                               *pass.max_applications_per_method);
                    }
                    for (std::uint32_t repeat = 0U; repeat < repetitions; ++repeat) {
                        state ^= state << 13U;
                        state ^= state >> 7U;
                        state ^= state << 17U;
                        bool appended = false;
                        if (id == "cfg.flattening" ||
                            id == "cfg.nested_flattening" ||
                            id == "cfg.multi_state_dispatch" ||
                            id == "cfg.table_dispatch" ||
                            id == "cfg.indirect_dispatch" ||
                            id == "cfg.mixed_ps_ss_if" ||
                            (id == "cfg.condition_expansion" &&
                             condition_expansion_selected) ||
                            (id == "cfg.conditional_nesting" &&
                             conditional_nesting_selected) ||
                            (id == "cfg.bogus_edges" &&
                             bogus_edges_selected) ||
                            (id == "cfg.dead_blocks" &&
                             dead_blocks_selected) ||
                            (id == "anti_analysis.path_explosion" &&
                             path_explosion_selected) ||
                            (id == "cfg.callback_style" &&
                             callback_style_selected) ||
                            (id == "cfg.loop_state_machine" &&
                             loop_state_machine_selected)) {
                            // The real flattening replacement is built after
                            // per-instruction rewrites have been collected.
                            // Do not substitute an entry-prefix switch when a
                            // method is not eligible for full block lowering.
                            appended = true;
                        } else if (id == "cfg.exception_dispatch" &&
                                   scratch_register.has_value() &&
                                   exception_helper_method.has_value() &&
                                   !core_runtime_helper) {
                            appended = assembler.AppendExceptionDispatch(
                                *scratch_register, *exception_helper_method,
                                state);
                        } else if (id == "cfg.block_reordering") {
                            if (flattening_selected && source_blocks > 1U) {
                                // Complete CFF already emits a seed-randomized
                                // physical case layout, including try methods.
                                appended = true;
                            } else if (source_blocks > 1U && code.tries.empty() &&
                                       code.debug_info_off == 0U) {
                                assembler.EnableBlockReordering(state);
                                appended = true;
                            }
                        } else if (id == "anti_analysis.pattern_randomization") {
                            assembler.EnableBlockReordering(state);
                            appended = scratch_register.has_value() &&
                                assembler.AppendPatternRandomization(
                                    *scratch_register,
                                    1U + static_cast<std::size_t>(state & 3U),
                                    state);
                            if (!appended && source_blocks > 1U) appended = true;
                        } else if (id == "anti_analysis.instruction_patterns" &&
                                   scratch_register.has_value() &&
                                   second_scratch.has_value()) {
                            appended = assembler.AppendInstructionPattern(
                                *scratch_register, *second_scratch, state);
                        } else if (id == "anti_analysis.ssa_pollution" &&
                                   predicate_register.has_value() &&
                                   scratch_register.has_value() &&
                                   second_scratch.has_value()) {
                            appended = assembler.AppendSsaPollution(
                                *predicate_register, *scratch_register,
                                *second_scratch, state);
                        } else if (id == "anti_analysis.dataflow_pollution" &&
                                   scratch_register.has_value() &&
                                   second_scratch.has_value()) {
                            appended = assembler.AppendDataflowPollution(
                                *scratch_register, *second_scratch, state);
                        } else if (id == "anti_analysis.register_shape" &&
                                   scratch_register.has_value() &&
                                   second_scratch.has_value()) {
                            appended = assembler.AppendRegisterShape(
                                *scratch_register, *second_scratch, state);
                        } else if (id == "anti_analysis.legal_exception_layout" &&
                                   scratch_register.has_value() &&
                                   exception_helper_method.has_value() &&
                                   !core_runtime_helper) {
                            appended = assembler.AppendExceptionDispatch(
                                *scratch_register, *exception_helper_method,
                                state);
                        } else if (id ==
                                       "anti_analysis.verifier_safe_overlap_substitute" &&
                                   scratch_register.has_value() &&
                                   exception_helper_method.has_value() &&
                                   !core_runtime_helper) {
                            appended = assembler.AppendSequentialExceptionMaze(
                                *scratch_register, *exception_helper_method,
                                state);
                        } else if (id ==
                                       "anti_analysis.legal_overlapping_handlers" &&
                                   predicate_register.has_value() &&
                                   scratch_register.has_value() &&
                                   exception_helper_method.has_value() &&
                                   !core_runtime_helper) {
                            appended = assembler.AppendSharedHandlerFanIn(
                                *predicate_register, *scratch_register,
                                *exception_helper_method, state);
                        } else if (id == "anti_analysis.decompiler_resilience" &&
                                   predicate_register.has_value() &&
                                   scratch_register.has_value() &&
                                   exception_helper_method.has_value() &&
                                   !core_runtime_helper) {
                            appended = assembler.AppendDecompilerMaze(
                                *predicate_register, *scratch_register,
                                *exception_helper_method, state);
                        }
                        if (!appended) break;
                        if (id != "cfg.flattening" &&
                            id != "cfg.nested_flattening" &&
                            id != "cfg.multi_state_dispatch" &&
                            id != "cfg.table_dispatch" &&
                            id != "cfg.indirect_dispatch" &&
                            id != "cfg.mixed_ps_ss_if" &&
                            id != "cfg.condition_expansion" &&
                            id != "cfg.conditional_nesting" &&
                            id != "cfg.bogus_edges" &&
                            id != "cfg.dead_blocks" &&
                            id != "anti_analysis.path_explosion" &&
                            id != "cfg.callback_style" &&
                            id != "cfg.loop_state_machine") {
                            ++pass_applications[std::string(id)];
                            method_cfg_changed = true;
                        }
                    }
                }
                for (std::size_t strategy = 0U;
                     !opaque_helper && !constant_helper &&
                     strategy < kRuntimeOpaquePasses.size();
                     ++strategy) {
                    const auto id = kRuntimeOpaquePasses[strategy];
                    const auto& pass = config.passes.at(std::string(id));
                    if (!pass.enabled) continue;
                    auto state = utils::StableHash64(
                        method_key, pass.seed.value_or(config.seed) ^
                                    (0x4f504151U + strategy));
                    const auto sample = static_cast<double>(state >> 11U) /
                                        static_cast<double>(
                                            std::uint64_t{1U} << 53U);
                    if (sample > pass.intensity) continue;
                    auto repetitions = 1U + static_cast<std::uint32_t>(
                        pass.intensity * 3.0);
                    if (dispatcher_materialization) repetitions = 1U;
                    if (pass.max_applications_per_method.has_value()) {
                        repetitions = std::min(
                            repetitions, *pass.max_applications_per_method);
                    }
                    for (std::uint32_t repeat = 0U; repeat < repetitions; ++repeat) {
                        state ^= state << 13U;
                        state ^= state >> 7U;
                        state ^= state << 17U;
                        bool appended = false;
                        if (scratch_register.has_value() &&
                            opaque_method_indices[strategy].has_value()) {
                            appended = assembler.AppendRuntimeOpaque(
                                *scratch_register,
                                *opaque_method_indices[strategy], state);
                        }
                        if (!appended) {
                            break;
                        }
                        ++pass_applications[std::string(id)];
                        method_cfg_changed = true;
                    }
                }
                const auto& automation_profile =
                    config.passes.at("strength.anti_automation_profile");
                const auto& analysis_profile =
                    config.passes.at("strength.analysis_cost_budget");
                const auto target_blocks = detail::StrengthPolicy::TargetBlocks(config);
                const bool require_exact_target =
                    detail::StrengthPolicy::RequiresFullStrength(config) ||
                    (analysis_profile.enabled &&
                     config.strength.target_analysis_cost_weeks != 0U);
                if (target_blocks != 0U && !flattening_selected) {
                    const auto blocks_before_strength = assembler.added_blocks();
                    auto state = utils::StableHash64(
                        method_key, automation_profile.seed.value_or(config.seed) ^
                                        0x4155544f4d415445ULL);
                    std::size_t iteration = 0U;
                    const auto append_runtime_opaque = [&]() {
                        if (opaque_helper || !scratch_register.has_value()) {
                            return false;
                        }
                        for (std::size_t offset = 0U;
                             offset < kRuntimeOpaquePasses.size(); ++offset) {
                            const auto strategy =
                                (iteration + offset +
                                 static_cast<std::size_t>(state)) %
                                kRuntimeOpaquePasses.size();
                            const auto& pass = config.passes.at(std::string(
                                kRuntimeOpaquePasses[strategy]));
                            if (!pass.enabled ||
                                !opaque_method_indices[strategy].has_value()) {
                                continue;
                            }
                            const auto appended = assembler.AppendRuntimeOpaque(
                                *scratch_register,
                                *opaque_method_indices[strategy], state);
                            if (appended) {
                                ++pass_applications[std::string(
                                    kRuntimeOpaquePasses[strategy])];
                            }
                            return appended;
                        }
                        return false;
                    };
                    while (assembler.added_blocks() < target_blocks) {
                        state ^= state << 13U;
                        state ^= state >> 7U;
                        state ^= state << 17U;
                        bool appended = false;
                        // Keep the exact strength budget affordable for DEX
                        // methods that already contain a large materialized
                        // CFG (string/runtime helpers are the common case).
                        // The compact form is still real executable code and
                        // contributes two reachable CFG blocks; reserve the
                        // larger exception/dataflow patterns for the tail so
                        // the final whole-method dispatcher remains legal.
                        const auto compact_budget_phase =
                            assembler.remaining_blocks() > 128U &&
                            scratch_register.has_value();
                        if (compact_budget_phase) {
                            appended = assembler.AppendCompactOpaqueSplit(
                                *scratch_register, state);
                        }
                        if (!appended) switch ((iteration + static_cast<std::size_t>(state & 7U)) &
                                7U) {
                            case 0U:
                                appended = append_runtime_opaque();
                                break;
                            case 1U:
                                if (scratch_register.has_value() &&
                                    second_scratch.has_value() &&
                                    config.passes.at(
                                        "anti_analysis.dataflow_pollution").enabled) {
                                    appended = assembler.AppendDataflowPollution(
                                        *scratch_register, *second_scratch,
                                        state);
                                    if (appended) {
                                        ++pass_applications[
                                            "anti_analysis.dataflow_pollution"];
                                    }
                                }
                                break;
                            case 2U:
                                if (scratch_register.has_value() &&
                                    second_scratch.has_value() &&
                                    config.passes.at(
                                        "anti_analysis.dataflow_pollution").enabled) {
                                    appended = assembler.AppendDataflowPollution(
                                        *scratch_register, *second_scratch,
                                        state);
                                    if (appended) {
                                        ++pass_applications[
                                            "anti_analysis.dataflow_pollution"];
                                    }
                                }
                                break;
                            case 3U:
                                if (scratch_register.has_value() &&
                                    exception_helper_method.has_value() &&
                                    !core_runtime_helper &&
                                    config.passes.at("cfg.exception_dispatch").enabled) {
                                    appended = assembler.AppendExceptionDispatch(
                                        *scratch_register,
                                        *exception_helper_method, state);
                                    if (appended) {
                                        ++pass_applications["cfg.exception_dispatch"];
                                    }
                                }
                                break;
                            case 4U:
                                appended = append_runtime_opaque();
                                break;
                            case 5U:
                                if (scratch_register.has_value() &&
                                    exception_helper_method.has_value() &&
                                    !core_runtime_helper &&
                                    config.passes.at(
                                        "cfg.exception_dispatch").enabled) {
                                    appended = assembler.AppendExceptionDispatch(
                                        *scratch_register,
                                        *exception_helper_method, state);
                                    if (appended) {
                                        ++pass_applications[
                                            "cfg.exception_dispatch"];
                                    }
                                }
                                break;
                            case 6U:
                                if (scratch_register.has_value() &&
                                    second_scratch.has_value() &&
                                    config.passes.at(
                                        "anti_analysis.register_shape").enabled) {
                                    appended = assembler.AppendRegisterShape(
                                        *scratch_register, *second_scratch,
                                        state);
                                    if (appended) {
                                        ++pass_applications[
                                            "anti_analysis.register_shape"];
                                    }
                                }
                                break;
                            case 7U:
                                if (scratch_register.has_value() &&
                                    exception_helper_method.has_value() &&
                                    !core_runtime_helper &&
                                    config.passes.at(
                                        "anti_analysis.verifier_safe_overlap_substitute").enabled) {
                                    appended = assembler.AppendSequentialExceptionMaze(
                                        *scratch_register,
                                        *exception_helper_method, state);
                                    if (appended) {
                                        ++pass_applications[
                                            "anti_analysis.verifier_safe_overlap_substitute"];
                                    }
                                }
                                break;
                        }
                        if (!appended) appended = append_runtime_opaque();
                        if (!appended && scratch_register.has_value() &&
                            second_scratch.has_value() &&
                            config.passes.at(
                                "anti_analysis.register_shape").enabled) {
                            appended = assembler.AppendRegisterShape(
                                *scratch_register, *second_scratch, state);
                            if (appended) {
                                ++pass_applications[
                                    "anti_analysis.register_shape"];
                            }
                        }
                        if (!appended && scratch_register.has_value() &&
                            assembler.remaining_blocks() == 2U) {
                            appended = assembler.AppendCompactOpaqueSplit(
                                *scratch_register, state);
                        }
                        if (!appended) break;
                        method_cfg_changed = true;
                        if (scratch_register.has_value() &&
                            (config.passes.at("data.constant_splitting").enabled ||
                             config.passes.at(
                                 "anti_analysis.constant_barriers").enabled) &&
                            (iteration & 3U) == 0U &&
                            assembler.AppendDataBarrier(*scratch_register, state)) {
                            method_data_changed = true;
                        }
                        ++iteration;
                    }
                    if (require_exact_target &&
                        assembler.added_blocks() != target_blocks) {
                        throw std::runtime_error(
                            "full-strength analysis budget could not be applied to " +
                            method_key + ": requested " +
                            std::to_string(target_blocks) + ", applied " +
                            std::to_string(assembler.added_blocks()));
                    }
                    const auto strength_blocks =
                        assembler.added_blocks() - blocks_before_strength;
                    if (strength_blocks != 0U) {
                        if (automation_profile.enabled &&
                            config.strength.anti_automation_profile) {
                            pass_applications["strength.anti_automation_profile"] +=
                                strength_blocks;
                        }
                        if (analysis_profile.enabled) {
                            pass_applications["strength.analysis_cost_budget"] +=
                                strength_blocks;
                        }
                    }
                }
                if (assembler.empty() && !flattening_selected) continue;
                cfg_blocks_added += assembler.added_blocks();
                auto prefix = std::move(assembler).Finish(encoded.code_off);
                bool complete_flattening_applied = false;
                if (flattening_selected) {
                    const auto materialized = materialized_layouts == nullptr ?
                        nullptr : [&]() -> const MaterializedRegisterLayout* {
                            const auto found = materialized_layouts->find(method_key);
                            return found == materialized_layouts->end() ?
                                nullptr : &found->second;
                        }();
                    // A runtime state barrier must never target the method
                    // currently being lowered.  The constant-runtime helper
                    // is itself eligible for the whole-method dispatcher; if
                    // it called its own barrier, every entry state would
                    // recurse before reaching the helper body.  This is the
                    // source of the repeated single-frame stack seen on ART.
                    auto runtime_state_barrier_method = constant_helper_method;
                    if (runtime_state_barrier_method.has_value() &&
                        *runtime_state_barrier_method == encoded.method_idx) {
                        runtime_state_barrier_method.reset();
                    }
                    std::optional<FlattenedReplacement> flattened;
                    try {
                        flattened = ControlFlowFlattener::BuildFlattenedReplacement(
                            dex_file, encoded, code, method_key,
                            prefix.code_units, prefix.try_regions,
                            prefix.linear_replacements, config,
                            FlatteningFeatures{
                                layered_dispatch_selected,
                                multi_state_dispatch_selected,
                                dispatcher_encoding,
                                condition_expansion_selected,
                                conditional_nesting_selected,
                                 bogus_edges_selected,
                                dead_blocks_selected,
                                path_explosion_selected,
                                !core_runtime_helper,
                                 callback_style_selected ?
                                     exception_helper_method : std::nullopt,
                                 runtime_state_barrier_method},
                            materialized);
                    } catch (const CffCodeBudgetExceeded& error) {
                        partition_failures.push_back({dex_file.method_key(encoded.method_idx), error.what()});
                        continue;
                    }
                    if (flattened.has_value()) {
                        const auto used_sparse_dispatch =
                            flattened->used_sparse_dispatch;
                        const auto used_packed_dispatch =
                            flattened->used_packed_dispatch;
                        const auto used_layered_dispatch =
                            flattened->used_layered_dispatch;
                        const auto used_multi_state_dispatch =
                            flattened->used_multi_state_dispatch;
                        const auto used_mixed_guard =
                            flattened->used_mixed_guard;
                        const auto expanded_conditions =
                            flattened->expanded_conditions;
                        const auto nested_conditions =
                            flattened->nested_conditions;
                        const auto bogus_edges = flattened->bogus_edges;
                        const auto dead_cases = flattened->dead_cases;
                        const auto exploded_conditions =
                            flattened->exploded_conditions;
                        prefix = std::move(flattened->code);
                        complete_flattening_applied = true;
                        ++flattened_methods;
                        if (base_flattening_selected) {
                            ++pass_applications["cfg.flattening"];
                        }
                        if (nested_dispatch_selected && used_layered_dispatch) {
                            ++pass_applications["cfg.nested_flattening"];
                        }
                        if (multi_state_dispatch_selected &&
                            used_multi_state_dispatch) {
                            ++pass_applications["cfg.multi_state_dispatch"];
                        }
                        if (table_dispatch_selected && used_packed_dispatch) {
                            ++pass_applications["cfg.table_dispatch"];
                        }
                        if (indirect_dispatch_selected && used_sparse_dispatch) {
                            ++pass_applications["cfg.indirect_dispatch"];
                        }
                        if (explicit_mixed_dispatch_selected && used_mixed_guard &&
                            used_sparse_dispatch && used_packed_dispatch) {
                            ++pass_applications["cfg.mixed_ps_ss_if"];
                        }
                        if (callback_style_selected && used_layered_dispatch) {
                            ++pass_applications["cfg.callback_style"];
                        }
                        pass_applications["cfg.condition_expansion"] +=
                            expanded_conditions;
                        pass_applications["cfg.conditional_nesting"] +=
                            nested_conditions;
                        pass_applications["cfg.bogus_edges"] += bogus_edges;
                        pass_applications["cfg.dead_blocks"] += dead_cases;
                        pass_applications["anti_analysis.path_explosion"] +=
                            exploded_conditions;
                        if (config.strength.anti_automation_profile &&
                            config.passes.at(
                                "strength.anti_automation_profile").enabled) {
                            pass_applications[
                                "strength.anti_automation_profile"] += dead_cases;
                        }
                        if (config.passes.at(
                                "strength.analysis_cost_budget").enabled) {
                            pass_applications[
                                "strength.analysis_cost_budget"] += dead_cases;
                        }
                        pass_applications["fake.calls"] +=
                            flattened->generated_calls;
                        if (loop_state_machine_selected) {
                            ++pass_applications["cfg.loop_state_machine"];
                        }
                        method_cfg_changed = true;
                    }
                }
                if (base_flattening_selected &&
                    !complete_flattening_applied) {
                    throw std::runtime_error(
                        "full-method CFF could not be applied without degradation to " +
                        method_key);
                }
                if (!prefix.code_units.empty() && !complete_flattening_applied) {
                    if (!scratch_register.has_value() ||
                        !second_scratch.has_value()) {
                        throw std::runtime_error(
                            "dedicated verifier-safe scratch registers are unavailable for " +
                            method_key);
                    }
                    constexpr std::uint16_t kScratchRegisterCount = 2U;
                    auto migration = ControlFlowFlattener::BuildParameterMigration(
                        dex_file, encoded, code, kScratchRegisterCount);
                    const auto migration_units = static_cast<std::uint32_t>(
                        migration.size());
                    if (migration_units != 0U) {
                        for (auto& region : prefix.try_regions) {
                            region.start_address += migration_units;
                            for (auto& handler : region.handlers) {
                                handler.address += migration_units;
                            }
                        }
                        auto materialized_prefix = migration;
                        materialized_prefix.insert(materialized_prefix.end(),
                                                   prefix.code_units.begin(),
                                                   prefix.code_units.end());
                        prefix.code_units = std::move(materialized_prefix);
                    }
                    prefix.replacement_registers_size =
                        static_cast<std::uint16_t>(code.registers_size +
                                                   kScratchRegisterCount);
                    if (produced_layouts != nullptr) {
                        const auto [_, inserted] = produced_layouts->emplace(
                            method_key,
                            MaterializedRegisterLayout{
                                *scratch_register, *second_scratch,
                                std::move(migration)});
                        if (!inserted) {
                            throw std::logic_error(
                                "duplicate materialized scratch layout for " +
                                method_key);
                        }
                    }
                }
                if (method_uses_constant_barrier) {
                    prefix.replacement_outs_size = std::max<std::uint16_t>(
                        code.outs_size, 1U);
                }
                if (prefix.code_units.empty() && !prefix.reorder_blocks &&
                    prefix.linear_replacements.empty() &&
                    !prefix.replacement_code_units.has_value()) {
                    continue;
                }
                prefixes.push_back(std::move(prefix));
                if (method_cfg_changed) ++cfg_changed;
                if (method_data_changed) ++data_changed;
            }
        };
        collect(data.direct_methods);
        collect(data.virtual_methods);
    }
    if (!partition_failures.empty()) throw CffPartitionRequired(std::move(partition_failures));
    return prefixes;
}

} // namespace

bool DexCodeLowering::HasControlFlowPasses(const GuardConfig& config) {
    return std::any_of(kControlFlowPasses.begin(), kControlFlowPasses.end(),
                       [&](const auto id) {
        return config.passes.at(std::string(id)).enabled;
    });
}

bool DexCodeLowering::HasInstructionPasses(const GuardConfig& config) {
    const auto opaque = std::any_of(
        kRuntimeOpaquePasses.begin(), kRuntimeOpaquePasses.end(),
        [&](const auto id) { return config.passes.at(std::string(id)).enabled; });
    return HasControlFlowPasses(config) || opaque ||
           config.passes.at("data.constant_splitting").enabled ||
           config.passes.at("data.boolean_arithmetic").enabled ||
           config.passes.at("anti_analysis.constant_barriers").enabled ||
           config.passes.at("anti_analysis.instruction_patterns").enabled;
}

DexLoweringResult DexCodeLowering::Apply(const dex::DexFile& source) const {
    DexLoweringResult result;
    result.bytes = source.Write();
    auto current = source;
    if (config_->passes.at("anti_analysis.debug_info_removal").enabled) {
        result.bytes = current.StripDebugInfo();
        current = dex::DexFile::Parse(result.bytes);
        result.debug_removed = true;
    }
    if (HasInstructionPasses(*config_)) {
        const auto run_phase = [&] (
            std::string_view phase_name,
            const GuardConfig& phase_config,
            const MaterializedRegisterLayouts* materialized_layouts = nullptr,
            MaterializedRegisterLayouts* produced_layouts = nullptr) {
            std::size_t cfg_methods = 0U;
            std::size_t flattened_methods = 0U;
            std::size_t cfg_blocks_added = 0U;
            std::size_t data_methods = 0U;
            std::size_t constants_rewritten = 0U;
            std::map<std::string, std::size_t, std::less<>> applications;
            const auto prefixes = BuildPrefixes(
                current, phase_config, cfg_methods, flattened_methods,
                cfg_blocks_added, data_methods, constants_rewritten,
                applications, materialized_layouts, produced_layouts);
            if (!prefixes.empty()) {
                try {
                    // RewriteCodePrefixes performs full verification before
                    // returning. Include that failure in the phase context.
                    result.bytes = dex::RewriteCodePrefixes(current, prefixes);
                    current = dex::DexFile::Parse(result.bytes);
                } catch (const std::exception& error) {
                    throw std::runtime_error(std::string(phase_name) +
                        " phase failed verification: " + error.what());
                }
            }
            // The dispatcher phase covers every method changed by the prefix
            // phase, so max is the unique method count rather than a double
            // count of the same protected method.
            result.cfg_methods = std::max(result.cfg_methods, cfg_methods);
            result.flattened_methods += flattened_methods;
            result.cfg_blocks_added += cfg_blocks_added;
            result.data_methods = std::max(result.data_methods, data_methods);
            result.constants_rewritten += constants_rewritten;
            for (const auto& [id, count] : applications) {
                result.pass_applications[id] += count;
            }
        };

        const auto has_whole_method_dispatcher = std::any_of(
            kWholeMethodDispatcherPasses.begin(),
            kWholeMethodDispatcherPasses.end(), [&](const auto id) {
                return config_->passes.at(std::string(id)).enabled;
            });
        if (!has_whole_method_dispatcher) {
            run_phase("instruction", *config_);
        } else {
            const auto linear = LinearRegionOutliner::Apply(current, *config_);
            if (!linear.bytes.empty()) {
                result.bytes = linear.bytes;
                current = dex::DexFile::Parse(result.bytes);
            }
            const auto regions = detail::CfgRegionOutliner::Apply(current, *config_);
            if (!regions.bytes.empty()) {
                result.bytes = regions.bytes;
                current = dex::DexFile::Parse(result.bytes);
            }
            // First materialize all predicates, exception mazes, fake calls,
            // data barriers and instruction rewrites into ordinary DEX CFG.
            auto materialize_config = *config_;
            for (const auto id : kWholeMethodDispatcherPasses) {
                materialize_config.passes.at(std::string(id)).enabled = false;
            }
            // The materialization pass prepares the CFG that the second phase
            // will flatten.  Its job is not to consume the final per-method
            // strength budget; applying the exact 1024-block policy here
            // would make tiny constructors fail before they reach the real
            // whole-method dispatcher.
            materialize_config.passes.at(
                "strength.analysis_cost_budget").enabled = false;
            materialize_config.strength.anti_automation_profile = false;
            materialize_config.strength.target_analysis_cost_weeks = 0U;
            // Then flatten that complete materialized CFG. No independent
            // prefix pass is allowed in this phase; every preceding block is
            // now a case in the main state machine.
            auto dispatcher_config = *config_;
            for (auto& [id, pass] : dispatcher_config.passes) {
                pass.enabled = false;
            }
            for (const auto id : kWholeMethodDispatcherPasses) {
                dispatcher_config.passes.at(std::string(id)) =
                    config_->passes.at(std::string(id));
            }
            for (const auto id : {"fake.classes", "fake.calls"}) {
                dispatcher_config.passes.at(id) = config_->passes.at(id);
            }
            for (const auto id : {"strength.anti_automation_profile",
                                  "strength.analysis_cost_budget"}) {
                dispatcher_config.passes.at(id) = config_->passes.at(id);
            }
            auto prepared = current;
            const auto checkpoint = result;
            for (std::size_t refinement = 0U;; ++refinement) {
                // Every trial starts before materialization. Reusing a failed
                // trial would double-apply protection and invalidate scratch
                // migration, try maps and pass-application statistics.
                current = prepared;
                result = checkpoint;
                result.bytes = prepared.Write();
                MaterializedRegisterLayouts materialized_layouts;
                run_phase("materialization", materialize_config, nullptr, &materialized_layouts);
                const auto outlined = ConstantProgramOutliner::Apply(current, *config_);
                if (!outlined.bytes.empty()) {
                    result.bytes = outlined.bytes;
                    current = dex::DexFile::Parse(result.bytes);
                }
                bool accepted = false;
                for (;;) {
                    try {
                        run_phase("dispatcher", dispatcher_config, &materialized_layouts);
                        accepted = true;
                        break;
                    } catch (const CffPartitionRequired& request) {
                        // First move complete constant programs even when the
                        // caller was below the old heuristic threshold. Typed
                        // barriers and caller registers remain unchanged.
                        const auto constants = CffPartitionPlanner::OutlineConstants(current, *config_, request);
                        if (!constants.bytes.empty()) {
                            result.bytes = constants.bytes;
                            current = dex::DexFile::Parse(result.bytes);
                            continue;
                        }
                        // Bounded, deterministic and fail-closed. No seed
                        // search, dead-state trimming or feature fallback.
                        if (refinement >= std::min<std::size_t>(32U, config_->budget.max_call_depth_increase))
                            throw std::length_error(std::string(request.what()) + "; partition depth exhausted");
                        const auto refined = CffPartitionPlanner::Refine(prepared, *config_, request);
                        prepared = dex::DexFile::Parse(refined.bytes);
                        break;
                    }
                }
                if (accepted) break;
            }
        }
    }
    const ScopeMatcher scope(config_->scope);
    const auto& automation_profile =
        config_->passes.at("strength.anti_automation_profile");
    const auto& analysis_profile =
        config_->passes.at("strength.analysis_cost_budget");
    const bool require_full_strength_cfg_floor =
        (config_->strength.anti_automation_profile &&
         automation_profile.enabled && automation_profile.intensity >= 1.0) ||
        (analysis_profile.enabled && analysis_profile.intensity >= 1.0);
    for (std::size_t class_index = 0U;
         class_index < current.classes().size(); ++class_index) {
        const auto owner = current.descriptor(
            current.classes()[class_index].class_idx);
        if (!scope.IsProtected(owner) ||
            !scope.AllowsCodeTransforms(owner)) {
            continue;
        }
        const auto& data = current.class_data(class_index);
        for (const auto* methods : {&data.direct_methods,
                                    &data.virtual_methods}) {
            for (const auto& method : *methods) {
                if (method.code_off == 0U) continue;
                const auto blocks = dex::BuildMethodIr(
                    dex::DecodeCodeItem(current, method.code_off))
                                        .blocks().size();
                const auto code_units = dex::DecodeCodeItem(
                    current, method.code_off).insns.size();
                if (require_full_strength_cfg_floor &&
                    code_units > kMaximumArtCompilerCodeUnits) {
                    throw std::runtime_error(
                        "ART compiler code-unit limit violated for " + owner +
                        current.method_key(method.method_idx) + ": " +
                        std::to_string(code_units) + " code units, maximum " +
                        std::to_string(kMaximumArtCompilerCodeUnits));
                }
                if (require_full_strength_cfg_floor &&
                    config_->passes.at("cfg.flattening").enabled &&
                    blocks < kMinimumFullStrengthCfgBlocks) {
                    throw std::runtime_error(
                        "full-strength CFF floor violated for " + owner +
                        current.method_key(method.method_idx) + ": " +
                        std::to_string(blocks) + " blocks, required " +
                        std::to_string(kMinimumFullStrengthCfgBlocks));
                }
                if (blocks >
                    config_->budget.max_analysis_blocks_per_method) {
                    throw std::runtime_error(
                        "output CFG exceeds max_analysis_blocks_per_method for " +
                        owner + current.method_key(method.method_idx));
                }
            }
        }
    }
    // Report decoded CFG growth, including dispatcher/edge gates. Counting only
    // prefix assembler blocks silently omitted the entire flattening phase.
    result.cfg_blocks_added = 0U;
    std::map<std::string, std::size_t, std::less<>> original_blocks;
    for (std::size_t class_index = 0U; class_index < source.classes().size();
         ++class_index) {
        const auto& before = source.class_data(class_index);
        for (const auto* methods : {&before.direct_methods, &before.virtual_methods})
            for (const auto& method : *methods)
                if (method.code_off != 0U)
                    original_blocks.emplace(source.method_key(method.method_idx),
                        dex::BuildMethodIr(dex::DecodeCodeItem(source, method.code_off)).blocks().size());
    }
    for (std::size_t class_index = 0U; class_index < current.classes().size(); ++class_index) {
        const auto& after = current.class_data(class_index);
        for (const auto* methods : {&after.direct_methods, &after.virtual_methods})
            for (const auto& method : *methods) {
                if (method.code_off == 0U) continue;
                const auto new_blocks = dex::BuildMethodIr(dex::DecodeCodeItem(current, method.code_off)).blocks().size();
                const auto found = original_blocks.find(current.method_key(method.method_idx));
                const auto old_blocks = found == original_blocks.end() ? 0U : found->second;
                if (new_blocks > old_blocks) result.cfg_blocks_added += new_blocks - old_blocks;
            }
    }
    dex::VerifyDexOrThrow(current, dex::VerificationLevel::Full);
    return result;
}

} // namespace birch::guard
