#include "birch/guard/dex_lowering.h"
#include "strength_policy.h"

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

#include "control_flow_flattener.h"
#include "cff_assembler.h"
#include "cff_code_budget.h"
#include "cff_switch_emitter.h"
#include "cff_type_domains.h"
#include "cff_transition_encoder.h"
#include "cff_joint_token.h"
#include "dead_state_router.h"

namespace birch::guard::detail {

bool ControlFlowFlattener::IsGeneratedCallDescriptor(std::string_view descriptor) {
    if (IsGuardGeneratedDescriptor(descriptor)) return true;
    return descriptor.size() >= 13U && descriptor[0] == 'L' &&
           descriptor[1] == 'a' && descriptor[10] == '/' &&
           descriptor[11] == 'a';
}


std::vector<std::uint16_t> ControlFlowFlattener::BuildParameterMigration(
    const dex::DexFile& dex_file, const dex::DexEncodedMethod& encoded,
    const dex::CodeItem& code, std::uint16_t register_delta) {
    std::vector<std::uint16_t> result;
    if (register_delta == 0U || code.ins_size == 0U) return result;

    const auto& method = dex_file.methods().at(encoded.method_idx);
    const auto old_parameter_base =
        static_cast<std::uint16_t>(code.registers_size - code.ins_size);
    std::vector<char> parameter_kinds;
    if ((encoded.access_flags & 0x0008U) == 0U) parameter_kinds.push_back('o');
    for (const auto type_idx : dex_file.type_list(
             dex_file.protos().at(method.proto_idx).parameters_off)) {
        const auto descriptor = dex_file.descriptor(type_idx);
        if (descriptor == "J" || descriptor == "D") {
            parameter_kinds.push_back('w');
        } else if (!descriptor.empty() &&
                   (descriptor.front() == 'L' || descriptor.front() == '[')) {
            parameter_kinds.push_back('o');
        } else {
            parameter_kinds.push_back('s');
        }
    }

    std::uint16_t word = 0U;
    result.reserve(parameter_kinds.size() * 2U);
    for (const auto kind : parameter_kinds) {
        const auto destination = static_cast<std::uint16_t>(
            old_parameter_base + word);
        const auto source = static_cast<std::uint16_t>(
            destination + register_delta);
        if (destination > 0xffU) {
            throw std::length_error(
                "parameter migration destination exceeds move/from16 encoding");
        }
        const auto opcode = kind == 'w' ? 0x05U : kind == 'o' ? 0x08U : 0x02U;
        result.insert(result.end(), {
            static_cast<std::uint16_t>(opcode | (destination << 8U)), source});
        word = static_cast<std::uint16_t>(word + (kind == 'w' ? 2U : 1U));
    }
    if (word != code.ins_size) {
        throw std::logic_error(
            "parameter word count disagrees with code_item ins_size");
    }
    return result;
}


std::optional<FlattenedReplacement> ControlFlowFlattener::BuildFlattenedReplacement(
    const dex::DexFile& dex_file, const dex::DexEncodedMethod& encoded,
    const dex::CodeItem& code, std::string_view method_key,
    std::span<const std::uint16_t> prefix_units,
    const std::vector<dex::CodePrefix::TryRegion>& prefix_tries,
    const std::map<std::uint32_t, std::vector<std::uint16_t>>& replacements,
    const GuardConfig& config, FlatteningFeatures features,
    const MaterializedRegisterLayout* materialized_layout) {
    const auto reject = [&](const char* reason)
        -> std::optional<FlattenedReplacement> {
        (void)reason;
        return std::nullopt;
    };
    // Runtime helpers are protected by the same CFF pipeline as application
    // methods, but a helper cannot use itself as the state barrier. Doing so
    // makes the first dispatcher state materialization recurse indefinitely on
    // ART. Keep the invariant at this lowering boundary so direct callers are
    // protected as well as the normal BuildPrefixes path.
    if (features.runtime_state_barrier_method.has_value() &&
        *features.runtime_state_barrier_method == encoded.method_idx) {
        features.runtime_state_barrier_method.reset();
    }
    // Keep generated call results in a private register. Reusing a dispatcher
    // register lets unrelated switch predecessors merge an int result with a
    // state/selector value and ART then observes Conflict at the next if-*z.
    const auto dispatcher_register_count = static_cast<std::uint16_t>(
        features.multi_state_dispatch ? 5U :
        features.dispatcher_encoding == DispatcherEncoding::Mixed ? 4U : 3U);
    const auto reused_scratch_count = static_cast<std::uint16_t>(
        materialized_layout != nullptr ? 2U : 0U);
    const auto register_delta = static_cast<std::uint16_t>(
        dispatcher_register_count - reused_scratch_count);
    if (code.registers_size > 255U - register_delta ||
        code.registers_size + register_delta >
            config.budget.max_registers_per_method) {
        return reject("register budget");
    }
    const auto ir = dex::BuildMethodIr(code);
    if (ir.blocks().empty() || ir.blocks().size() > 0xffffU) {
        return reject("empty/oversized CFG");
    }
    std::vector<bool> source_reachable(ir.blocks().size(), false);
    std::vector<dex::BlockId> pending_reachability{ir.entry()};
    while (!pending_reachability.empty()) {
        const auto block = pending_reachability.back();
        pending_reachability.pop_back();
        if (source_reachable[block]) continue;
        source_reachable[block] = true;
        for (const auto& edge : ir.blocks()[block].successors)
            pending_reachability.push_back(edge.target);
    }

    std::map<std::uint32_t, const dex::DecodedInstruction*> decoded;
    std::map<std::uint32_t, const dex::DecodedInstruction*> payloads;
    for (const auto& instruction : code.instructions) {
        if (instruction.kind != dex::InstructionKind::Payload) {
            decoded.emplace(instruction.offset, &instruction);
        } else {
            payloads.emplace(instruction.offset, &instruction);
        }
    }
    std::map<std::uint32_t, dex::BlockId> block_by_start;
    for (const auto& block : ir.blocks()) {
        block_by_start.emplace(block.start_offset, block.id);
    }
    std::set<dex::BlockId> exception_handlers;
    for (const auto& region : code.tries) {
        for (const auto& handler : region.handlers) {
            const auto found = block_by_start.find(handler.address);
            if (found == block_by_start.end()) return reject("missing catch handler block");
            exception_handlers.insert(found->second);
        }
    }
    if (exception_handlers.contains(ir.entry())) return reject("entry is catch handler");
    for (const auto& block : ir.blocks()) {
        for (const auto& edge : block.successors) {
            if (edge.kind != dex::IrEdgeKind::Exception &&
                exception_handlers.contains(edge.target)) {
                return reject("normal edge enters catch handler");
            }
        }
    }
    const bool complete_dispatcher_phase = materialized_layout != nullptr;
    // ART merges register types from every switch predecessor even when a
    // state is not reachable at runtime. Directly targeting arbitrary
    // business blocks from the entry domain therefore makes legitimate
    // predecessor-defined locals undefined. Keep the per-type-domain edge
    // dispatcher and harden it with runtime state barriers and decoy states.
    const bool central_loop_dispatch = false;

    std::vector<std::uint32_t> states(ir.blocks().size());
    std::set<std::uint32_t> used_states;
    for (const auto& block : ir.blocks()) {
        auto mixed = utils::StableHash64(
            std::string(method_key) + ':' + std::to_string(block.start_offset),
            config.seed ^ 0x4346464449535041ULL);
        auto candidate = static_cast<std::uint32_t>(mixed & 0x7fffffffU);
        if (candidate == 0U) candidate = 1U;
        while (!used_states.insert(candidate).second) {
            candidate = candidate == 0x7fffffffU ? 1U : candidate + 1U;
        }
        states[block.id] = candidate;
    }

    // Reserve a separate one-shot state only for an explicitly supplied
    // lowering prefix. Production lowering materializes prefixes in a first
    // pass and then flattens the resulting CFG, so this path is normally
    // empty. Parameter migration must execute before the first verifier merge.
    const bool has_prefix_prologue = !prefix_units.empty();
    auto prologue_state = states.at(ir.entry());
    if (has_prefix_prologue) {
        prologue_state = static_cast<std::uint32_t>(utils::StableHash64(
            std::string(method_key) + ":prologue",
            config.seed ^ 0x50524f4c4f475545ULL) & 0x7fffffffU);
        if (prologue_state == 0U) prologue_state = 1U;
        while (!used_states.insert(prologue_state).second) {
            prologue_state = prologue_state == 0x7fffffffU ? 1U : prologue_state + 1U;
        }
    }

    std::vector<dex::BlockId> dispatched_blocks;
    dispatched_blocks.reserve(ir.blocks().size());
    for (const auto& block : ir.blocks()) {
        if (!exception_handlers.contains(block.id)) {
            dispatched_blocks.push_back(block.id);
        }
    }
    const auto layered_dispatch = features.layered_dispatch &&
                                  dispatched_blocks.size() >= 2U;
    const auto desired_buckets = std::max<std::size_t>(
        3U, static_cast<std::size_t>(std::ceil(std::sqrt(
            static_cast<double>(dispatched_blocks.size())))));
    const auto bucket_count = layered_dispatch ?
        std::min<std::size_t>(
            std::min<std::size_t>(16U, desired_buckets),
            dispatched_blocks.size()) : 1U;
    std::vector<std::vector<dex::BlockId>> bucket_blocks(bucket_count);
    std::vector<std::size_t> bucket_by_block(ir.blocks().size(), 0U);
    std::sort(dispatched_blocks.begin(), dispatched_blocks.end(),
              [&](const auto left, const auto right) {
        return std::tie(states[left], left) < std::tie(states[right], right);
    });
    for (std::size_t index = 0U; index < dispatched_blocks.size(); ++index) {
        const auto bucket = index % bucket_count;
        const auto block = dispatched_blocks[index];
        bucket_blocks[bucket].push_back(block);
        bucket_by_block[block] = bucket;
    }
    if (features.dispatcher_encoding == DispatcherEncoding::Packed ||
        features.dispatcher_encoding == DispatcherEncoding::Mixed) {
        const auto room = static_cast<std::uint32_t>(
            0x3fffffffU - dispatched_blocks.size());
        // A multiple of the bucket count removes a redundant subtraction in
        // every typed transition tail. States remain seed-keyed and dense;
        // bucket membership and every runtime guard are unchanged.
        const auto base = static_cast<std::uint32_t>(bucket_count) * (1U + static_cast<std::uint32_t>(
            utils::StableHash64(method_key,
                                config.seed ^ 0x5041434b45445354ULL) % (room / bucket_count)));
        for (std::size_t index = 0U; index < dispatched_blocks.size(); ++index) {
            states[dispatched_blocks[index]] =
                base + static_cast<std::uint32_t>(index);
        }
    }
    std::vector<std::uint32_t> bucket_states(bucket_count);
    std::set<std::uint32_t> used_bucket_states;
    for (std::size_t bucket = 0U; bucket < bucket_count; ++bucket) {
        auto mixed = utils::StableHash64(
            std::string(method_key) + ":bucket:" + std::to_string(bucket),
            config.seed ^ 0x4255434b455453ULL);
        auto candidate = static_cast<std::uint32_t>(mixed & 0x7fffffffU);
        if (candidate == 0U) candidate = 1U;
        while (!used_bucket_states.insert(candidate).second) {
            candidate = candidate == 0x7fffffffU ? 1U : candidate + 1U;
        }
        bucket_states[bucket] = candidate;
    }
    if (layered_dispatch &&
        (features.dispatcher_encoding == DispatcherEncoding::Packed ||
         features.dispatcher_encoding == DispatcherEncoding::Mixed)) {
        const auto room = static_cast<std::uint32_t>(
            0x3fffffffU - bucket_count);
        const auto base = 1U + static_cast<std::uint32_t>(
            utils::StableHash64(method_key,
                                config.seed ^ 0x5041434b45444255ULL) % room);
        for (std::size_t bucket = 0U; bucket < bucket_count; ++bucket) {
            bucket_states[bucket] = base + static_cast<std::uint32_t>(bucket);
        }
    }

    CffAssembler assembler;
    const auto dispatcher = assembler.NewLabel();
    const auto dead_dispatcher = assembler.NewLabel();
    const auto trap = assembler.NewLabel();
    const auto prologue = assembler.NewLabel();
    std::vector<CffAssembler::Label> bucket_dispatchers;
    if (layered_dispatch) {
        bucket_dispatchers.resize(bucket_count);
        for (auto& label : bucket_dispatchers) label = assembler.NewLabel();
    }
    std::vector<CffAssembler::Label> cases(ir.blocks().size());
    for (auto& label : cases) label = assembler.NewLabel();
    std::vector<CffAssembler::Label> entry_case_gates(ir.blocks().size());
    for (auto& label : entry_case_gates) label = assembler.NewLabel();
    const auto entry_target = [&](dex::BlockId block) {
        return central_loop_dispatch ? cases[block] : entry_case_gates[block];
    };
    const auto& automation_profile =
        config.passes.at("strength.anti_automation_profile");
    const auto& analysis_profile =
        config.passes.at("strength.analysis_cost_budget");
    const auto strength_intensity = std::max(
        config.strength.anti_automation_profile && automation_profile.enabled ?
            automation_profile.intensity : 0.0,
        analysis_profile.enabled ? analysis_profile.intensity : 0.0);
    const bool full_strength_floor =
        (config.strength.anti_automation_profile &&
         automation_profile.enabled && automation_profile.intensity >= 1.0) ||
        (analysis_profile.enabled && analysis_profile.intensity >= 1.0);
    if (full_strength_floor) assembler.UseCompactBranches();
    if (full_strength_floor &&
        config.budget.max_added_blocks_per_method <
            kMinimumFullStrengthCfgBlocks) {
        return reject("full-strength CFG floor exceeds block budget");
    }
    const auto emit_dead_case = features.dead_blocks || features.bogus_edges ||
                                strength_intensity > 0.0 || full_strength_floor;
    const auto dead_intensity = std::max({
        features.dead_blocks ?
            config.passes.at("cfg.dead_blocks").intensity : 0.0,
        features.bogus_edges ?
            config.passes.at("cfg.bogus_edges").intensity : 0.0,
        strength_intensity});
    auto dead_state_count = emit_dead_case ? std::max<std::size_t>(
        1U + static_cast<std::size_t>(std::ceil(dead_intensity * 63.0)),
        static_cast<std::size_t>(std::ceil(
            dead_intensity * static_cast<double>(
                config.budget.max_added_blocks_per_method)))) : 0U;
    // Respect the requested target, including the calibrated analysis target.
    // A structural minimum is not a substitute for a larger configured target.
    dead_state_count = std::max(dead_state_count,
        detail::StrengthPolicy::TargetBlocks(config));
    const auto dead_case_count = dead_state_count;
    std::vector<CffAssembler::Label> dead_cases(dead_case_count);
    for (auto& label : dead_cases) label = assembler.NewLabel();
    std::vector<std::uint32_t> dead_states(dead_state_count);
    std::vector<std::size_t> dead_primary(dead_state_count);
    std::vector<std::size_t> dead_secondary(dead_state_count);
    if (!dead_cases.empty()) {
        if (features.dispatcher_encoding == DispatcherEncoding::Packed ||
            features.dispatcher_encoding == DispatcherEncoding::Mixed) {
            const auto first = states.at(dispatched_blocks.back()) + 1U;
            if (first > 0x7fffffffU - dead_cases.size()) return reject("dead state overflow");
            for (std::size_t index = 0U; index < dead_states.size(); ++index) {
                dead_states[index] = first + static_cast<std::uint32_t>(index);
            }
        } else {
            for (std::size_t index = 0U; index < dead_states.size(); ++index) {
                auto candidate = static_cast<std::uint32_t>(utils::StableHash64(
                    std::string(method_key) + ":dead:" +
                        std::to_string(index),
                    config.seed ^ 0x4445414443415345ULL) & 0x7fffffffU);
                if (candidate == 0U) candidate = 1U;
                while (!used_states.insert(candidate).second) {
                    candidate = candidate == 0x7fffffffU ? 1U : candidate + 1U;
                }
                dead_states[index] = candidate;
            }
        }
        for (std::size_t index = 0U; index < dead_states.size(); ++index) {
            const auto choose = [&](std::uint64_t tag) {
                if (index == 0U) return dead_states.size();
                if (dead_states.size() <= 1U) return dead_states.size();
                auto candidate = static_cast<std::size_t>(utils::StableHash64(
                    std::string(method_key) + ":dead-edge:" +
                        std::to_string(index) + ":" + std::to_string(tag),
                    config.seed ^ 0x4445414447524150ULL) %
                        std::min<std::size_t>(index, 64U));
                // Bound fan-in without introducing cycles. Choosing among all
                // preceding states concentrates most edges in the first hub.
                candidate = index - 1U - candidate;
                return candidate;
            };
            dead_primary[index] = choose(0U);
            dead_secondary[index] = choose(1U);
        }
    }

    const auto state_register = materialized_layout != nullptr ?
        materialized_layout->first_scratch : code.registers_size;
    const auto selector_register = materialized_layout != nullptr ?
        materialized_layout->second_scratch :
        static_cast<std::uint16_t>(code.registers_size + 1U);
    const auto extra_register_base = materialized_layout != nullptr ?
        code.registers_size : static_cast<std::uint16_t>(code.registers_size + 2U);
    const auto guard_register = extra_register_base;
    const auto joint_register = extra_register_base;
    const auto joint_guard_register = static_cast<std::uint16_t>(
        extra_register_base + 1U);
    const auto call_result_register = static_cast<std::uint16_t>(
        code.registers_size + register_delta - 1U);
    const auto joint_mask = static_cast<std::uint32_t>(utils::StableHash64(
        std::string(method_key) + ":joint-mask",
        config.seed ^ 0x4a4f494e54535441ULL));
    // Generated-call results are only consumed in the one-way dead CFG.
    // Until then this private register holds the full-width immutable mask.
    // It is neither an application local nor a shared verifier-domain hub.
    const auto cached_joint_mask = features.multi_state_dispatch ?
        std::optional<std::uint16_t>(call_result_register) : std::nullopt;
    const CffJointToken joint_tokens(assembler, joint_mask, cached_joint_mask);
    const auto emit_joint_token = [&]() {
        if (!features.multi_state_dispatch) return;
        // Derive the joint token from the actual runtime barrier result,
        // rather than emitting a foldable copy of the expected constants.
        joint_tokens.Emit(joint_register, state_register, selector_register);
    };
    const auto& method = dex_file.methods().at(encoded.method_idx);
    std::optional<std::uint16_t> generated_call_method;
    if (features.generated_calls &&
        (config.passes.at("fake.classes").enabled ||
         config.passes.at("fake.calls").enabled)) {
        for (std::uint32_t candidate = 0U;
             candidate < dex_file.methods().size(); ++candidate) {
            const auto& candidate_method = dex_file.methods()[candidate];
            const auto candidate_owner = dex_file.descriptor(
                candidate_method.class_idx);
            if (!ControlFlowFlattener::IsGeneratedCallDescriptor(candidate_owner) ||
                candidate_owner == dex_file.descriptor(method.class_idx) ||
                dex_file.proto_key(candidate_method.proto_idx) != "()I" ||
                dex_file.string(candidate_method.name_idx) == "<init>" ||
                dex_file.string(candidate_method.name_idx) == "<clinit>" ||
                candidate > std::numeric_limits<std::uint16_t>::max()) {
                continue;
            }
            bool has_code = false;
            for (std::size_t candidate_class = 0U;
                 candidate_class < dex_file.classes().size() && !has_code;
                 ++candidate_class) {
                const auto& candidate_data = dex_file.class_data(candidate_class);
                for (const auto* group : {&candidate_data.direct_methods,
                                           &candidate_data.virtual_methods}) {
                    for (const auto& encoded_candidate : *group) {
                        if (encoded_candidate.method_idx == candidate &&
                            encoded_candidate.code_off != 0U) {
                            has_code = true;
                            break;
                        }
                    }
                    if (has_code) break;
                }
            }
            if (has_code) {
                generated_call_method = static_cast<std::uint16_t>(candidate);
                break;
            }
        }
    }
    assembler.Emit(ControlFlowFlattener::BuildParameterMigration(
        dex_file, encoded, code, register_delta));
    std::uint32_t hoisted_prologue_units = 0U;
    if (materialized_layout != nullptr) {
        if (materialized_layout->parameter_prologue.size() >
                code.insns.size() ||
            !std::equal(materialized_layout->parameter_prologue.begin(),
                        materialized_layout->parameter_prologue.end(),
                        code.insns.begin())) {
            throw std::logic_error(
                "materialized scratch prologue does not match method entry");
        }
        assembler.Emit(materialized_layout->parameter_prologue);
        hoisted_prologue_units = static_cast<std::uint32_t>(
            materialized_layout->parameter_prologue.size());
        // Switch cases are verifier-reachable independently. Give private
        // scratch registers a stable integer type before the dispatcher.
        assembler.EmitConst32(materialized_layout->first_scratch, 0x13579bdfU);
        assembler.EmitConst32(materialized_layout->second_scratch, 0x2468ace0U);
    }
    if (cached_joint_mask) assembler.EmitConst32(*cached_joint_mask, joint_mask);
    std::size_t generated_calls = 0U;
    const auto emit_generated_call = [&]() {
        if (!generated_call_method.has_value()) return;
        assembler.Emit({0x0071U, *generated_call_method, 0U,
                        static_cast<std::uint16_t>(
                            0x0aU | (call_result_register << 8U))});
        ++generated_calls;
    };
    std::optional<dex::CodePrefix::TryRegion> synthetic_exception_try;

    CffSwitchEmitter dispatchers(assembler, trap);
    const auto emit_dispatcher = [&](std::uint16_t reg,
                                     std::vector<std::uint32_t> keys,
                                     std::vector<CffAssembler::Label> targets,
                                     bool packed,
                                     std::optional<CffAssembler::Label>
                                         invalid_target = std::nullopt,
                                     bool inline_default = false) {
        dispatchers.Emit(reg, std::move(keys), std::move(targets), packed,
                         invalid_target, inline_default);
    };

    std::uint32_t prefix_base = 0U;
    assembler.EmitRuntimeEncodedState(
        state_register, has_prefix_prologue ? prologue_state : states.at(ir.entry()),
        config.seed ^ 0x50524f4c4f475553ULL,
        features.runtime_state_barrier_method);
    if (layered_dispatch) {
        assembler.EmitEncodedState(
            selector_register,
            has_prefix_prologue ? bucket_states.front() :
                bucket_states.at(bucket_by_block.at(ir.entry())),
            config.seed ^ 0x50524f4c4f475542ULL);
        emit_joint_token();
    }
    assembler.EmitGoto32(dispatcher);

    // Keep the dispatcher physically adjacent to the entry jump.  The case
    // labels are bound below, while the switch payload offsets are resolved
    // after the complete method has been laid out.
    assembler.Bind(dispatcher);
    if (layered_dispatch) {
        const auto outer_packed =
            !has_prefix_prologue &&
            (features.dispatcher_encoding == DispatcherEncoding::Packed ||
             features.dispatcher_encoding == DispatcherEncoding::Mixed);
        std::vector<std::uint32_t> outer_keys;
        std::vector<CffAssembler::Label> outer_targets;
        outer_keys.reserve(dispatched_blocks.size() + dead_states.size() +
                           static_cast<std::size_t>(has_prefix_prologue));
        outer_targets.reserve(outer_keys.capacity());
        if (has_prefix_prologue) {
            outer_keys.push_back(prologue_state);
            outer_targets.push_back(bucket_dispatchers.front());
        }
        for (const auto block : dispatched_blocks) {
            outer_keys.push_back(states[block]);
            outer_targets.push_back(bucket_dispatchers[bucket_by_block[block]]);
        }
        // Dead tokens share their own dispatcher; duplicating its entire
        // table here costs thousands of units without adding graph edges.
        emit_dispatcher(state_register, std::move(outer_keys),
                        std::move(outer_targets), outer_packed, dead_dispatcher);
        for (std::size_t bucket = 0U; bucket < bucket_count; ++bucket) {
            assembler.Bind(bucket_dispatchers[bucket]);
            if (features.multi_state_dispatch) {
                joint_tokens.Guard(joint_guard_register, joint_register,
                                   state_register, selector_register, trap);
            }
            if (features.dispatcher_encoding == DispatcherEncoding::Mixed) {
                assembler.EmitConst32(guard_register, bucket_states[bucket]);
                assembler.EmitXor(guard_register, selector_register, guard_register);
                assembler.EmitIf16(static_cast<std::uint16_t>(
                    0x39U | (guard_register << 8U)), trap);
            }
            std::vector<std::uint32_t> keys;
            std::vector<CffAssembler::Label> targets;
            keys.reserve(bucket_blocks[bucket].size());
            targets.reserve(bucket_blocks[bucket].size());
            if (bucket == 0U && has_prefix_prologue) {
                keys.push_back(prologue_state);
                targets.push_back(prologue);
            }
            for (const auto block : bucket_blocks[bucket]) {
                keys.push_back(states[block]);
                targets.push_back(entry_target(block));
            }
            emit_dispatcher(state_register, std::move(keys),
                            std::move(targets), false);
        }
    } else {
        std::vector<std::uint32_t> keys;
        std::vector<CffAssembler::Label> targets;
        keys.reserve(dispatched_blocks.size() + dead_states.size());
        targets.reserve(dispatched_blocks.size() + dead_states.size());
        if (has_prefix_prologue) {
            keys.push_back(prologue_state);
            targets.push_back(prologue);
        }
        for (const auto block : dispatched_blocks) {
            keys.push_back(states[block]);
            targets.push_back(entry_target(block));
        }
        emit_dispatcher(state_register, std::move(keys),
                        std::move(targets),
                        features.dispatcher_encoding == DispatcherEncoding::Packed,
                        dead_dispatcher);
    }

    for (const auto block : dispatched_blocks) {
        if (central_loop_dispatch) {
            // Central dispatch targets the business cases directly. Do not
            // materialize hundreds of unreferenced goto-trap islands.
            assembler.Bind(entry_case_gates[block]);
        } else if (block == ir.entry()) {
            assembler.Bind(entry_case_gates[block]);
            assembler.EmitGoto32(cases[block]);
        }
    }

    if (has_prefix_prologue) {
        assembler.Bind(prologue);
        prefix_base = static_cast<std::uint32_t>(assembler.position());
        assembler.Emit(prefix_units);
        assembler.EmitRuntimeEncodedState(
            state_register, states.at(ir.entry()), config.seed ^ 0x454e545259U,
            features.runtime_state_barrier_method);
        if (layered_dispatch) {
            assembler.EmitEncodedState(
                selector_register,
                bucket_states.at(bucket_by_block.at(ir.entry())),
                config.seed ^ 0x454e54525942554bULL);
            emit_joint_token();
        }
        assembler.EmitGoto32(dispatcher);
    }

    const auto entry_dispatch_units = assembler.position();
    std::vector<dex::BlockId> layout;
    layout.reserve(ir.blocks().size());
    for (const auto& block : ir.blocks()) layout.push_back(block.id);
    std::sort(layout.begin(), layout.end(), [&](const auto left,
                                                const auto right) {
        const auto left_hash = utils::StableHash64(
            std::string(method_key) + ':' + std::to_string(left),
            config.seed ^ 0x4c41594f5554ULL);
        const auto right_hash = utils::StableHash64(
            std::string(method_key) + ':' + std::to_string(right),
            config.seed ^ 0x4c41594f5554ULL);
        return std::tie(left_hash, left) < std::tie(right_hash, right);
    });

    std::vector<CffAssembler::Label> typed_dispatchers(ir.blocks().size());
    std::vector<CffAssembler::Label> typed_invalid(ir.blocks().size());
    std::vector<std::vector<dex::BlockId>> typed_targets(ir.blocks().size());
    const std::array excluded_registers{state_register, selector_register};
    // Shared live domains are hardened by the independent dead candidates.
    // Profiles without that graph retain their original per-source dispatch.
    const CffTypeDomains type_domains(dex_file, encoded, ir, excluded_registers,
                                      !dead_states.empty(), true);
    for (std::size_t block = 0U; block < ir.blocks().size(); ++block) {
        typed_dispatchers[block] = assembler.NewLabel();
        typed_invalid[block] = assembler.NewLabel();
    }
    // Factoring is safe only inside exact verifier domains. Sparse states
    // have no arithmetic bucket projection and retain their original path.
    const bool shared_transition_tails = complete_dispatcher_phase && full_strength_floor &&
        layered_dispatch && features.dispatcher_encoding != DispatcherEncoding::Sparse;
    std::vector<CffTransitionEncoder> transition_encoders;
    if (shared_transition_tails) {
        transition_encoders.reserve(ir.blocks().size());
        for (std::size_t source = 0U; source < ir.blocks().size(); ++source) {
            transition_encoders.emplace_back(assembler,
                CffTransitionEncoder::Registers{state_register, selector_register,
                    joint_register, joint_guard_register},
                states.at(dispatched_blocks.front()), bucket_states.front(),
                static_cast<std::uint8_t>(bucket_count), joint_mask,
                features.multi_state_dispatch, typed_dispatchers[source], typed_invalid[source],
                utils::StableHash64(std::string(method_key) + ":transition:" +
                    std::to_string(source), config.seed),
                features.runtime_state_barrier_method, features.callback_helper_method,
                cached_joint_mask);
        }
    }
    const auto emit_transition = [&](dex::BlockId source, dex::BlockId target,
                                     std::uint64_t salt) {
        auto& targets = typed_targets.at(type_domains.Owner(source));
        if (std::find(targets.begin(), targets.end(), target) == targets.end()) {
            targets.push_back(target);
        }
        if (shared_transition_tails) {
            transition_encoders.at(type_domains.Owner(source)).Emit(states.at(target));
            return;
        }
        const auto invalid = typed_invalid.at(source);
        if (features.callback_helper_method.has_value()) {
            assembler.Emit({0x0071U, *features.callback_helper_method, 0U,
                            static_cast<std::uint16_t>(
                                0x0aU | (selector_register << 8U))});
            assembler.EmitIf16(static_cast<std::uint16_t>(
                0x38U | (selector_register << 8U)), invalid);
        }
        assembler.EmitRuntimeEncodedState(
            state_register, states.at(target), salt,
            features.runtime_state_barrier_method);
        if (layered_dispatch) {
            assembler.EmitEncodedState(
                selector_register,
                bucket_states.at(bucket_by_block.at(target)),
                salt ^ 0x53454c4543544f52ULL);
            emit_joint_token();
        }
        assembler.EmitGoto32(central_loop_dispatch ? dispatcher :
                             typed_dispatchers.at(type_domains.Owner(source)));
    };
    struct PendingSwitch {
        std::size_t instruction_offset{};
        std::uint16_t payload_ident{};
        std::vector<std::int32_t> keys;
        std::vector<CffAssembler::Label> targets;
    };
    struct PendingFillArray {
        std::size_t instruction_offset{};
        std::vector<std::uint16_t> payload;
    };
    struct CopiedInstruction {
        dex::BlockId block{};
        std::uint32_t old_offset{};
        std::uint32_t old_width{};
        std::uint32_t new_start{};
        std::uint32_t new_end{};
    };
    std::vector<PendingSwitch> pending_switches;
    std::vector<PendingFillArray> pending_fill_arrays;
    std::vector<CopiedInstruction> copied_instructions;
    std::size_t transformed_conditions = 0U;
    for (const auto block_id : layout) {
        const auto& block = ir.blocks().at(block_id);
        assembler.Bind(cases.at(block_id));
        // Verifiers also inspect disconnected original components with an
        // undefined initial register frame. Such a component can feed a
        // shared typed tail, so establish the immutable mask there as well.
        // Normal entry/exception paths keep the single hoisted definition.
        // move-exception must remain the first instruction in a handler;
        // its mask is initialized immediately after that instruction below.
        const bool cold_mask = cached_joint_mask && !source_reachable[block_id];
        if (cold_mask && !exception_handlers.contains(block_id))
            assembler.EmitConst32(*cached_joint_mask, joint_mask);
        const auto& tail = *decoded.at(block.instructions.back().dex_offset);
        const auto copy_instruction = [&](const dex::IrInstruction& instruction) {
            if (instruction.dex_offset < hoisted_prologue_units) return;
            const auto new_start = assembler.position();
            const auto replacement = replacements.find(instruction.dex_offset);
            if (replacement != replacements.end()) {
                assembler.Emit(replacement->second);
            } else if (instruction.dex_opcode == 0x1aU) {
                // A later rename/canonical ID remap can move any string past
                // index 65535. Emit the final-width form now, before layout,
                // payload alignment and the exact partition budget are fixed.
                // This preserves the register and value and prevents remapping
                // from growing branches or crossing the runtime code limit.
                if (instruction.encoded.size() != 2U)
                    throw std::logic_error("CFF const-string has invalid width");
                assembler.Emit({static_cast<std::uint16_t>(
                    (instruction.encoded.front() & 0xff00U) | 0x1bU),
                    instruction.encoded[1U], 0U});
            } else if (instruction.dex_opcode == 0x26U) {
                if (instruction.encoded.size() != 3U) {
                    throw std::logic_error(
                        "CFF fill-array-data instruction has invalid width");
                }
                const auto raw = static_cast<std::uint32_t>(
                    instruction.encoded[1U]) |
                    static_cast<std::uint32_t>(instruction.encoded[2U]) << 16U;
                const auto displacement = static_cast<std::int32_t>(raw);
                const auto target = static_cast<std::int64_t>(
                    instruction.dex_offset) + displacement;
                if (target < 0 || target >
                        std::numeric_limits<std::uint32_t>::max()) {
                    throw std::logic_error(
                        "CFF fill-array-data target is out of range");
                }
                const auto found = payloads.find(
                    static_cast<std::uint32_t>(target));
                if (found == payloads.end() ||
                    found->second->code_units.empty() ||
                    found->second->code_units.front() != 0x0300U) {
                    throw std::logic_error(
                        "CFF fill-array-data payload is missing");
                }
                assembler.Emit({instruction.encoded.front(), 0U, 0U});
                pending_fill_arrays.push_back(
                    {new_start, found->second->code_units});
            } else if (instruction.dex_opcode == 0x00U &&
                       instruction.encoded.size() == 1U &&
                       instruction.encoded.front() == 0U) {
                // A canonical source nop has no semantic payload.  Preserve
                // its one-unit shape with a real fallthrough branch so CFF
                // output never reintroduces decorative nop instructions.
                assembler.Emit({0x0128U});
            } else {
                assembler.Emit(instruction.encoded);
            }
            if (cold_mask && instruction.dex_opcode == 0x0dU)
                assembler.EmitConst32(*cached_joint_mask, joint_mask);
            copied_instructions.push_back({
                block_id, instruction.dex_offset,
                decoded.at(instruction.dex_offset)->width,
                static_cast<std::uint32_t>(new_start),
                static_cast<std::uint32_t>(assembler.position())});
        };
        for (std::size_t i = 0U; i + 1U < block.instructions.size(); ++i) {
            copy_instruction(block.instructions[i]);
        }
        std::vector<dex::IrEdge> normal_edges;
        std::copy_if(block.successors.begin(), block.successors.end(),
                     std::back_inserter(normal_edges), [](const auto& edge) {
            return edge.kind != dex::IrEdgeKind::Exception;
        });
        const auto salt = utils::StableHash64(
            std::string(method_key) + ':' + std::to_string(block.start_offset),
            config.seed ^ 0x5452414e534954ULL);
        if (tail.kind == dex::InstructionKind::Return ||
            tail.kind == dex::InstructionKind::Throw) {
            copy_instruction(block.instructions.back());
        } else if (tail.kind == dex::InstructionKind::UnconditionalBranch) {
            if (normal_edges.size() != 1U) return reject("unconditional edge shape");
            emit_transition(block_id, normal_edges.front().target, salt);
        } else if (tail.kind == dex::InstructionKind::ConditionalBranch) {
            const auto branch = std::find_if(
                normal_edges.begin(), normal_edges.end(), [](const auto& edge) {
                    return edge.kind == dex::IrEdgeKind::Branch;
                });
            const auto fallthrough = std::find_if(
                normal_edges.begin(), normal_edges.end(), [](const auto& edge) {
                    return edge.kind == dex::IrEdgeKind::Fallthrough;
                });
            if (branch == normal_edges.end() || fallthrough == normal_edges.end()) {
                return reject("conditional edge shape");
            }
            const auto true_transition = assembler.NewLabel();
            const auto false_transition = assembler.NewLabel();
            const auto original_first = tail.code_units.front();
            const auto inverse_first = static_cast<std::uint16_t>(
                (tail.code_units.front() & 0xff00U) |
                InverseIfOpcode(tail.opcode));
            assembler.EmitIf16(inverse_first, false_transition);
            const auto expansion_budget =
                (features.condition_expansion ?
                    2U + static_cast<std::uint32_t>(std::ceil(
                        config.passes.at("cfg.condition_expansion").intensity *
                        6.0)) : 0U) +
                (features.path_explosion ?
                    8U + static_cast<std::uint32_t>(std::ceil(
                        config.passes.at("anti_analysis.path_explosion").intensity *
                        24.0)) : 0U);
            const auto nesting_budget = features.conditional_nesting ?
                4U + static_cast<std::uint32_t>(std::ceil(
                    config.passes.at("cfg.conditional_nesting").intensity *
                    12.0)) : 0U;
            // A large materialized method already has hundreds of dispatcher
            // cases.  Bound per-branch decoration by the remaining DEX method
            // budget so the complete state machine stays valid at the same
            // configured strength instead of overflowing the 65K-unit limit.
            const auto complexity_cap = complete_dispatcher_phase ? 1U :
                code.insns.size() > 1200U ?
                (transformed_conditions < 8U ? 2U : 0U) :
                std::numeric_limits<std::uint32_t>::max();
            const auto expansion_rounds = std::min(expansion_budget, complexity_cap);
            const auto nesting_rounds = std::min(nesting_budget, complexity_cap);
            const auto contradiction = typed_invalid.at(block_id);
            // Expansion is a flat chain of redundant checks. Every check is
            // equivalent to the source predicate and the contradictory arm
            // goes to a real dead/trap state.
            for (std::uint32_t round = 0U; round < expansion_rounds; ++round) {
                const auto validated = assembler.NewLabel();
                assembler.EmitIf16(original_first, validated);
                assembler.EmitGoto32(contradiction);
                assembler.Bind(validated);
            }
            // Nesting is deliberately separate from expansion: each branch
            // arm enters the next guard only through the preceding guard's
            // continuation label, producing a nested CFG rather than another
            // flat repetition counter.
            for (std::uint32_t round = 0U; round < nesting_rounds; ++round) {
                const auto nested = assembler.NewLabel();
                assembler.EmitIf16(inverse_first, contradiction);
                assembler.EmitIf16(original_first, nested);
                assembler.EmitGoto32(contradiction);
                assembler.Bind(nested);
            }
            if (features.bogus_edges) {
                assembler.EmitIf16(inverse_first, contradiction);
            }
            assembler.EmitGoto32(true_transition);
            assembler.Bind(false_transition);
            for (std::uint32_t round = 0U; round < expansion_rounds; ++round) {
                const auto validated = assembler.NewLabel();
                assembler.EmitIf16(inverse_first, validated);
                assembler.EmitGoto32(contradiction);
                assembler.Bind(validated);
            }
            for (std::uint32_t round = 0U; round < nesting_rounds; ++round) {
                const auto nested = assembler.NewLabel();
                assembler.EmitIf16(original_first, contradiction);
                assembler.EmitIf16(inverse_first, nested);
                assembler.EmitGoto32(contradiction);
                assembler.Bind(nested);
            }
            if (features.bogus_edges) {
                assembler.EmitIf16(original_first, contradiction);
            }
            emit_transition(block_id, fallthrough->target,
                            salt ^ 0x46414c5345ULL);
            assembler.Bind(true_transition);
            emit_transition(block_id, branch->target,
                            salt ^ 0x54525545ULL);
            ++transformed_conditions;
        } else if (tail.kind == dex::InstructionKind::Switch) {
            const auto fallthrough = std::find_if(
                normal_edges.begin(), normal_edges.end(), [](const auto& edge) {
                    return edge.kind == dex::IrEdgeKind::Fallthrough;
                });
            if (fallthrough == normal_edges.end() ||
                tail.code_units.size() != 3U) {
                return reject("switch instruction shape");
            }
            const auto relative = static_cast<std::int32_t>(
                static_cast<std::uint32_t>(tail.code_units.at(1U)) |
                static_cast<std::uint32_t>(tail.code_units.at(2U)) << 16U);
            const auto payload64 = static_cast<std::int64_t>(tail.offset) +
                                   relative;
            if (payload64 < 0 ||
                payload64 >= static_cast<std::int64_t>(code.insns.size())) {
                return reject("switch payload range");
            }
            const auto payload_at = static_cast<std::size_t>(payload64);
            const auto ident = code.insns.at(payload_at);
            if ((ident != 0x0100U && ident != 0x0200U) ||
                payload_at + 2U > code.insns.size()) {
                return reject("switch payload kind");
            }
            const auto count = code.insns.at(payload_at + 1U);
            if (count != tail.targets.size()) return reject("switch target count");
            std::vector<std::int32_t> keys;
            keys.reserve(count);
            const auto read_i32 = [&](std::size_t at) {
                if (at + 2U > code.insns.size()) {
                    throw std::out_of_range("CFF switch payload is truncated");
                }
                return static_cast<std::int32_t>(
                    static_cast<std::uint32_t>(code.insns[at]) |
                    static_cast<std::uint32_t>(code.insns[at + 1U]) << 16U);
            };
            if (ident == 0x0100U) {
                const auto first_key = read_i32(payload_at + 2U);
                for (std::uint32_t i = 0U; i < count; ++i) {
                    keys.push_back(static_cast<std::int32_t>(
                        static_cast<std::uint32_t>(first_key) + i));
                }
            } else {
                for (std::uint32_t i = 0U; i < count; ++i) {
                    keys.push_back(read_i32(payload_at + 2U + i * 2U));
                }
            }
            const auto switch_at = assembler.position();
            assembler.Emit({tail.code_units.front(), 0U, 0U});
            emit_transition(block_id, fallthrough->target,
                            salt ^ 0x44454641554c54ULL);
            std::vector<CffAssembler::Label> target_labels;
            target_labels.reserve(count);
            for (std::size_t i = 0U; i < count; ++i) {
                const auto target = block_by_start.find(tail.targets.at(i));
                if (target == block_by_start.end()) return reject("missing switch target block");
                const auto transition = assembler.NewLabel();
                target_labels.push_back(transition);
                assembler.Bind(transition);
                emit_transition(block_id, target->second,
                                salt ^ (0x43415345ULL + i));
            }
            pending_switches.push_back(
                {switch_at, ident, std::move(keys), std::move(target_labels)});
        } else {
            copy_instruction(block.instructions.back());
            const auto fallthrough = std::find_if(
                normal_edges.begin(), normal_edges.end(), [](const auto& edge) {
                    return edge.kind == dex::IrEdgeKind::Fallthrough;
                });
            if (fallthrough == normal_edges.end()) {
                // Alignment nops before a payload can form an unreachable
                // executable island with no successor. Keep it unreachable
                // and route a hypothetical entry to the invalid-state trap.
                assembler.EmitGoto32(trap);
            } else {
                emit_transition(block_id, fallthrough->target, salt);
            }
        }
    }

    const auto body_end = assembler.position();
    std::size_t transition_units = 0U;
    for (std::size_t source = 0U; source < typed_targets.size(); ++source) {
        const auto tail_begin = assembler.position();
        if (shared_transition_tails) transition_encoders[source].Bind(true);
        transition_units += assembler.position() - tail_begin;
        const auto& successors = typed_targets[source];
        if (central_loop_dispatch) {
            // Labels are still bound so the generic transition builder can
            // share one code path, but central-loop methods never emit the
            // per-source payloads that made the old form locally recoverable.
            assembler.Bind(typed_dispatchers[source]);
            continue;
        }
        if (successors.empty()) {
            assembler.Bind(typed_dispatchers[source]);
            continue;
        }
        assembler.Bind(typed_dispatchers[source]);
        if (layered_dispatch && features.multi_state_dispatch) {
            joint_tokens.Guard(joint_guard_register, joint_register,
                               state_register, selector_register, typed_invalid[source]);
        }
        std::vector<std::uint32_t> keys;
        std::vector<CffAssembler::Label> targets;
        keys.reserve(successors.size());
        targets.reserve(successors.size());
        for (const auto target : successors) {
            keys.push_back(states.at(target));
            targets.push_back(cases.at(target));
        }
        // Do not expose a source block's exact successor set as a 1-2 case
        // signature. Mix in independently keyed dead-state candidates so a
        // local payload parse no longer recovers the original edge set.
        if (!dead_states.empty()) {
            const auto decoy_count = std::min<std::size_t>(
                type_domains.MemberCount(static_cast<dex::BlockId>(source)), dead_states.size());
            std::set<std::size_t> selected_decoys;
            for (std::size_t decoy = 0U;
                 selected_decoys.size() < decoy_count; ++decoy) {
                const auto candidate = static_cast<std::size_t>(
                    utils::StableHash64(
                        std::string(method_key) + ":typed-decoy:" +
                            std::to_string(source) + ":" +
                            std::to_string(decoy),
                        config.seed ^ 0x5459504544444543ULL) %
                    dead_states.size());
                if (!selected_decoys.insert(candidate).second) continue;
                keys.push_back(dead_states[candidate]);
                targets.push_back(dead_cases[candidate]);
            }
        }
        emit_dispatcher(state_register, std::move(keys), std::move(targets),
                        false, typed_invalid[source]);
    }

    const auto typed_dispatch_units = assembler.position() - body_end - transition_units;
    const auto invalid_entries_begin = assembler.position();
    DeadStateRouter dead_edges(assembler, state_register, dead_states, dead_cases,
        features.dispatcher_encoding != DispatcherEncoding::Sparse,
        utils::StableHash64(method_key, config.seed ^ 0x444541444445434fULL));
    // Invalid live tokens acquire a valid dead token before leaving their
    // verifier type domain. No empty per-source goto-to-one-trap stubs.
    for (std::size_t source = 0U; source < typed_invalid.size(); ++source) {
        if (source != 0U && source % 16U == 0U) dead_edges.FlushLocalDecoders();
        const bool entry_gate_used = !central_loop_dispatch && source != ir.entry() &&
            std::find(dispatched_blocks.begin(), dispatched_blocks.end(), source) !=
                dispatched_blocks.end();
        if (entry_gate_used) assembler.Bind(entry_case_gates[source]);
        assembler.Bind(typed_invalid[source]);
        if (!entry_gate_used && !assembler.HasBranchTo(typed_invalid[source])) continue;
        if (dead_states.empty()) {
            assembler.EmitGoto16(trap);
            continue;
        }
        const auto target = static_cast<std::size_t>(utils::StableHash64(
            std::string(method_key) + ":invalid:" + std::to_string(source),
            config.seed ^ 0x494e56414c4944ULL) % dead_states.size());
        dead_edges.EmitEntry(target);
    }
    dead_edges.FlushLocalDecoders();
    const auto invalid_entry_units = assembler.position() - invalid_entries_begin;
    if (!dead_states.empty()) {
        assembler.Bind(dead_dispatcher);
        dead_edges.EmitSelector(selector_register);
        std::vector<std::uint32_t> keys;
        std::vector<CffAssembler::Label> targets;
        for (std::size_t i = 0; i < dead_edges.shards().size(); ++i) {
            if (dead_edges.shards()[i].keys.empty()) continue;
            keys.push_back(static_cast<std::uint32_t>(i));
            targets.push_back(dead_edges.shards()[i].dispatcher);
        }
        emit_dispatcher(selector_register, std::move(keys), std::move(targets), false, trap, true);
        const auto fallback_shard = static_cast<std::size_t>(config.seed %
            dead_edges.shards().size());
        // Sparse shard selection can leave empty buckets. Select an occupied
        // fallback deterministically without changing any valid routing key.
        auto occupied = fallback_shard;
        while (dead_edges.shards()[occupied].keys.empty())
            occupied = (occupied + 1U) % dead_edges.shards().size();
        dead_edges.EmitFallback(occupied, config.seed ^ 0x524f4f5444454641ULL);
    } else {
        assembler.Bind(dead_dispatcher);
        assembler.EmitGoto32(trap);
    }

    const auto dead_cases_begin = assembler.position();
    for (std::size_t index = 0U; index < dead_cases.size(); ++index) {
        // High-register absolute tokens use one extra unit. Keep all keyed
        // islands inside signed 8-bit range, including calls/conditional arms.
        const auto island_nodes = state_register <= 15U ? 24U : 12U;
        if (index != 0U && index % island_nodes == 0U) dead_edges.FlushLocalDecoders();
        assembler.Bind(dead_cases[index]);
        // Dead/contradictory paths remain executable DEX and deliberately
        // call a generated runtime class.  This keeps bogus branches tied to
        // a real call graph instead of reducing them to empty padding.
        if (index == 0U &&
            config.passes.at("cfg.exception_dispatch").enabled &&
            config.budget.max_added_try_regions_per_method != 0U) {
            // Keep the synthetic exception edge inside its own dead state.
            // Covering the business body with a catch-all changes observable
            // exception semantics and can turn a recoverable exception into a
            // permanent dispatcher loop.
            const auto try_start = static_cast<std::uint32_t>(
                assembler.position());
            emit_generated_call();
            assembler.EmitConst32(call_result_register, 0U);
            assembler.Emit({static_cast<std::uint16_t>(
                0x27U | (call_result_register << 8U))});
            const auto try_end = static_cast<std::uint32_t>(
                assembler.position());
            const auto handler = try_end;
            assembler.Emit({static_cast<std::uint16_t>(
                0x0dU | (call_result_register << 8U))});
            emit_generated_call();
            synthetic_exception_try = dex::CodePrefix::TryRegion{
                try_start, try_end - try_start,
                {{std::nullopt, handler}}};
        } else if (index % 8U == 0U) {
            emit_generated_call();
        }
        // Dead states form a keyed graph with two independently chosen
        // successors.  The branch is fed by the generated call result when
        // available, so the graph is not an index+1 chain and cannot be
        // removed by a simple linear-pattern pass. Both successors remain
        // verifier-safe dispatcher states and eventually reach trap.
        const auto emit_dead_transition = [&](std::size_t target) {
            if (target >= dead_states.size()) {
                assembler.EmitGoto16(trap);
                return;
            }
            // Dead-node transitions intentionally avoid the shared barrier:
            // applying a four-unit runtime call to all 256 decoys would
            // consume the ART budget without increasing the business CFG.
            const auto edge_salt = config.seed ^ dead_states[index] ^
                (0x4445434f59535441ULL + target);
            // Dead paths must never feed the business dispatcher. ART treats
            // every switch target as reachable from every predecessor and a
            // dead-to-business back edge poisons live local types at entry.
            dead_edges.EmitEdge(dead_states[index], target, edge_salt);
        };
        if (generated_call_method.has_value() && dead_states.size() > 1U &&
            (index % 8U) == 0U) {
            const auto primary = assembler.NewLabel();
            assembler.EmitIf16(static_cast<std::uint16_t>(
                                  0x38U | (call_result_register << 8U)),
                              primary);
            emit_dead_transition(dead_secondary.at(index));
            assembler.Bind(primary);
            emit_dead_transition(dead_primary.at(index));
        } else {
            emit_dead_transition(dead_primary.at(index));
        }
    }

    dead_edges.FlushLocalDecoders();
    const auto dead_cases_units = assembler.position() - dead_cases_begin;
    const auto shards_begin = assembler.position();
    for (std::size_t i = 0; i < dead_edges.shards().size(); ++i) {
        dead_edges.BindShard(i);
        const auto& shard = dead_edges.shards()[i];
        if (shard.keys.empty()) {
            continue;
        }
        emit_dispatcher(state_register, shard.keys, shard.targets, dead_edges.packed(), trap, true);
        dead_edges.EmitFallback(i, config.seed ^ (0x5348415244444546ULL + i));
    }
    assembler.Bind(trap);
    emit_generated_call();
    // An invalid dispatcher token is an invariant violation. Re-entering the
    // dispatcher with the same invalid token creates an unbounded trap loop;
    // fail closed after retaining the generated call edge instead.
    assembler.EmitConst32(call_result_register, 0U);
    assembler.Emit({static_cast<std::uint16_t>(
        0x27U | (call_result_register << 8U))});
    const auto shard_units = assembler.position() - shards_begin;
    const auto payloads_begin = assembler.position();
    // All dispatch keys and encodings are now fixed. Plan their exact widths
    // and parity padding before allocating payloads; never trim dead states.
    auto planned_end = payloads_begin;
    for (const auto& pending : pending_switches) {
        planned_end = CffAssembler::AlignedPayloadPosition(planned_end, state_register);
        planned_end += pending.payload_ident == 0x0100U ?
            4U + 2U * pending.keys.size() : 2U + 4U * pending.keys.size();
    }
    planned_end = dispatchers.PlannedPayloadEnd(planned_end, state_register);
    for (const auto& pending : pending_fill_arrays) {
        planned_end = CffAssembler::AlignedPayloadPosition(planned_end, state_register);
        planned_end += pending.payload.size();
    }
    CffCodeBudget code_budget(config, code.insns.size());
    code_budget.Reserve("entry", entry_dispatch_units);
    code_budget.Reserve("business", body_end - entry_dispatch_units);
    code_budget.Reserve("transitions", transition_units);
    code_budget.Reserve("typed", typed_dispatch_units);
    code_budget.Reserve("invalid", invalid_entry_units);
    code_budget.Reserve("dead_router", dead_cases_begin - invalid_entries_begin - invalid_entry_units);
    code_budget.Reserve("dead_cases", dead_cases_units);
    code_budget.Reserve("shards", shard_units);
    code_budget.Reserve("payloads", planned_end - payloads_begin);
    if (!code_budget.Fits()) {
        if (full_strength_floor) code_budget.Require(method_key, dead_states.size());
        return reject("code size budget");
    }
    std::vector<std::size_t> rewritten_payload_offsets;
    rewritten_payload_offsets.reserve(pending_switches.size());
    for (const auto &pending : pending_switches) {
      assembler.AlignPayload(state_register);
      rewritten_payload_offsets.push_back(assembler.position());
      assembler.Emit({pending.payload_ident,
                      static_cast<std::uint16_t>(pending.keys.size())});
      if (pending.payload_ident == 0x0100U) {
        if (pending.keys.empty())
          return reject("empty source switch payload");
        const auto first = static_cast<std::uint32_t>(pending.keys.front());
        assembler.Emit({static_cast<std::uint16_t>(first),
                        static_cast<std::uint16_t>(first >> 16U)});
      } else {
        for (const auto key : pending.keys) {
          const auto bits = static_cast<std::uint32_t>(key);
          assembler.Emit({static_cast<std::uint16_t>(bits),
                          static_cast<std::uint16_t>(bits >> 16U)});
        }
      }
      for (const auto target : pending.targets) {
        const auto target_position = assembler.LabelPosition(target);
        if (!target_position.has_value()) {
          throw std::logic_error("CFF switch transition is unbound");
        }
        const auto displacement =
            static_cast<std::int64_t>(*target_position) -
            static_cast<std::int64_t>(pending.instruction_offset);
        if (displacement < std::numeric_limits<std::int32_t>::min() ||
            displacement > std::numeric_limits<std::int32_t>::max()) {
          throw std::length_error("CFF switch case exceeds int32");
        }
        const auto bits =
            static_cast<std::uint32_t>(static_cast<std::int32_t>(displacement));
        assembler.Emit({static_cast<std::uint16_t>(bits),
                        static_cast<std::uint16_t>(bits >> 16U)});
      }
    }
    dispatchers.EmitPayloads(state_register);
    std::vector<std::size_t> fill_array_payload_offsets;
    fill_array_payload_offsets.reserve(pending_fill_arrays.size());
    for (const auto &pending : pending_fill_arrays) {
      assembler.AlignPayload(state_register);
      fill_array_payload_offsets.push_back(assembler.position());
      assembler.Emit(pending.payload);
    }
    std::vector<dex::CodePrefix::TryRegion> replacement_tries;
    replacement_tries.reserve(prefix_tries.size() + code.tries.size());
    for (const auto& region : prefix_tries) {
        auto relocated = region;
        relocated.start_address += prefix_base;
        for (auto& handler : relocated.handlers) {
            handler.address += prefix_base;
        }
        replacement_tries.push_back(std::move(relocated));
    }
    for (const auto& region : code.tries) {
        for (const auto block_id : layout) {
            std::vector<const CopiedInstruction*> protected_spans;
            for (const auto& copied : copied_instructions) {
                if (copied.block == block_id &&
                    copied.old_offset >= region.start_address &&
                    copied.old_offset <
                        region.start_address + region.instruction_count) {
                    protected_spans.push_back(&copied);
                }
            }
            if (protected_spans.empty()) continue;
            std::vector<dex::CodePrefix::CatchHandler> handlers;
            handlers.reserve(region.handlers.size());
            for (const auto& handler : region.handlers) {
                const auto handler_block = block_by_start.find(handler.address);
                if (handler_block == block_by_start.end()) return reject("missing try handler block");
                const auto handler_position =
                    assembler.LabelPosition(cases.at(handler_block->second));
                if (!handler_position.has_value()) {
                    throw std::logic_error("CFF catch handler is unbound");
                }
                handlers.push_back({
                    handler.type_idx,
                    static_cast<std::uint32_t>(*handler_position)});
            }
            const auto start = protected_spans.front()->new_start;
            const auto end = protected_spans.back()->new_end;
            replacement_tries.push_back(
                {start, end - start, std::move(handlers)});
        }
    }
    if (synthetic_exception_try.has_value()) {
        replacement_tries.push_back(std::move(*synthetic_exception_try));
    }
    if (replacement_tries.size() >
        code.tries.size() + config.budget.max_added_try_regions_per_method) {
        return reject("try region budget");
    }
    auto units = std::move(assembler).Finish();
    code_budget.Reconcile(units.size());
    for (std::size_t i = 0U; i < pending_switches.size(); ++i) {
        const auto displacement =
            static_cast<std::int64_t>(rewritten_payload_offsets.at(i)) -
            static_cast<std::int64_t>(pending_switches.at(i).instruction_offset);
        const auto bits = static_cast<std::uint32_t>(
            static_cast<std::int32_t>(displacement));
        units.at(pending_switches.at(i).instruction_offset + 1U) =
            static_cast<std::uint16_t>(bits);
        units.at(pending_switches.at(i).instruction_offset + 2U) =
            static_cast<std::uint16_t>(bits >> 16U);
    }
    dispatchers.PatchPayloads(units);
    for (std::size_t i = 0U; i < pending_fill_arrays.size(); ++i) {
        const auto displacement = static_cast<std::int64_t>(
            fill_array_payload_offsets.at(i)) -
            static_cast<std::int64_t>(
                pending_fill_arrays.at(i).instruction_offset);
        if (displacement < std::numeric_limits<std::int32_t>::min() ||
            displacement > std::numeric_limits<std::int32_t>::max()) {
            throw std::length_error(
                "CFF fill-array-data payload exceeds int32");
        }
        const auto bits = static_cast<std::uint32_t>(
            static_cast<std::int32_t>(displacement));
        const auto instruction_at =
            pending_fill_arrays.at(i).instruction_offset;
        units.at(instruction_at + 1U) = static_cast<std::uint16_t>(bits);
        units.at(instruction_at + 2U) = static_cast<std::uint16_t>(
            bits >> 16U);
    }
    FlattenedReplacement replacement;
    replacement.code.code_off = encoded.code_off;
    replacement.code.replacement_code_units = std::move(units);
    replacement.code.replacement_registers_size = static_cast<std::uint16_t>(
        code.registers_size + register_delta);
    if (features.runtime_state_barrier_method.has_value()) {
        replacement.code.replacement_outs_size = std::max<std::uint16_t>(
            code.outs_size, 1U);
    }
    replacement.code.replacement_try_regions = std::move(replacement_tries);
    replacement.used_sparse_dispatch = dispatchers.used_sparse();
    replacement.used_packed_dispatch = dispatchers.used_packed();
    replacement.used_layered_dispatch = layered_dispatch;
    replacement.used_multi_state_dispatch =
        layered_dispatch && features.multi_state_dispatch;
    replacement.used_mixed_guard = layered_dispatch &&
        features.dispatcher_encoding == DispatcherEncoding::Mixed;
    replacement.expanded_conditions = features.condition_expansion ?
        transformed_conditions : 0U;
    replacement.nested_conditions = features.conditional_nesting ?
        transformed_conditions : 0U;
    replacement.bogus_edges = features.bogus_edges ?
        transformed_conditions : 0U;
    replacement.dead_cases = dead_states.size();
    replacement.exploded_conditions = features.path_explosion ?
        transformed_conditions : 0U;
    replacement.generated_calls = generated_calls;
    return replacement;
}

} // namespace birch::guard::detail
