#include "birch/dex/builder.h"
#include "birch/dex/cfg.h"
#include "birch/dex/code.h"
#include "birch/dex/ir.h"
#include "birch/dex/verifier.h"
#include "birch/guard/dex_lowering.h"
#include "birch/guard/constant_runtime.h"
#include "birch/guard/model_lowering.h"
#include "birch/guard/opaque_runtime.h"
#include "support/int_dex_interpreter.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

int main() {
    birch::dex::DexBuilder builder(38U);
    birch::dex::ClassSpec klass;
    klass.descriptor = "Llowering/Business;";
    birch::dex::MethodSpec method;
    method.name = "execute";
    method.access_flags = 0x0001U;
    method.body.registers_size = 4U;
    method.body.ins_size = 1U;
    method.body.code_units.assign(32U, 0x0000U);
    method.body.code_units.push_back(0x000eU);
    klass.virtual_methods.push_back(std::move(method));
    builder.AddClass(std::move(klass));
    const auto source = birch::dex::DexFile::Parse(builder.Build());

    const auto config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 123456,
      "scope": {"protect": [{"pattern": "Llowering/**;"}], "keep": []},
      "budget": {"max_method_growth_ratio": 64.0},
      "passes": {
        "cfg.flattening": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.nested_flattening": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.multi_state_dispatch": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.bogus_edges": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.loop_state_machine": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.condition_expansion": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.conditional_nesting": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.table_dispatch": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.indirect_dispatch": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.mixed_ps_ss_if": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.exception_dispatch": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.callback_style": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "cfg.dead_blocks": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "anti_analysis.pattern_randomization": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "anti_analysis.dataflow_pollution": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "anti_analysis.path_explosion": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "anti_analysis.ssa_pollution": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "anti_analysis.instruction_patterns": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "anti_analysis.register_shape": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "anti_analysis.legal_exception_layout": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "anti_analysis.verifier_safe_overlap_substitute": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "anti_analysis.decompiler_resilience": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "anti_analysis.legal_overlapping_handlers": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1}
      }
    })json");
    const auto modeled = birch::guard::DexModelLowering(config).Apply(source);
    const auto modeled_source = birch::dex::DexFile::Parse(modeled.bytes);
    const auto lowered = birch::guard::DexCodeLowering(config).Apply(
        modeled_source);
    assert(lowered.cfg_methods == 1U);
    const auto output = birch::dex::DexFile::Parse(lowered.bytes);
    birch::dex::VerifyDexOrThrow(output, birch::dex::VerificationLevel::Full);
    const auto business_class = std::find_if(
        output.classes().begin(), output.classes().end(), [&](const auto& item) {
            return output.descriptor(item.class_idx) == "Llowering/Business;";
        });
    assert(business_class != output.classes().end());
    const auto business_index = static_cast<std::size_t>(
        std::distance(output.classes().begin(), business_class));
    const auto code = birch::dex::DecodeCodeItem(
        output,
        output.class_data(business_index).virtual_methods.front().code_off);
    const auto contains_opcode = [&](std::uint8_t opcode) {
        return std::any_of(code.instructions.begin(), code.instructions.end(),
                           [&](const auto& instruction) {
            return instruction.opcode == opcode;
        });
    };
    assert(code.insns.size() > 160U);
    assert(contains_opcode(0x2bU)); // packed-switch dispatcher
    assert(contains_opcode(0x2cU)); // sparse-switch dispatcher
    assert(contains_opcode(0x27U)); // exception dispatcher
    assert(lowered.pass_applications.at("cfg.loop_state_machine") == 0U);
    for (const auto* id : {
             "anti_analysis.pattern_randomization",
             "anti_analysis.dataflow_pollution",
             "anti_analysis.ssa_pollution",
             "anti_analysis.instruction_patterns",
             "anti_analysis.register_shape",
             "anti_analysis.legal_exception_layout",
             "anti_analysis.verifier_safe_overlap_substitute",
             "anti_analysis.decompiler_resilience",
             "anti_analysis.legal_overlapping_handlers"}) {
        assert(lowered.pass_applications.at(id) != 0U);
    }
    assert(!code.tries.empty());
    assert(std::none_of(
        code.instructions.begin(), code.instructions.end(),
        [](const auto& instruction) {
            return instruction.kind != birch::dex::InstructionKind::Payload &&
                   instruction.opcode == 0x00U;
        }));
    const auto exception_helper_name =
        birch::guard::RuntimeExceptionMethodName(123456U);
    const auto helper_method = std::find_if(
        output.methods().begin(), output.methods().end(), [&](const auto& item) {
            return output.string(item.name_idx) == exception_helper_name &&
                   output.proto_key(item.proto_idx) == "()I";
        });
    assert(helper_method != output.methods().end());
    const auto helper_method_index = static_cast<std::uint16_t>(
        std::distance(output.methods().begin(), helper_method));
    const auto is_helper_invoke = [&](const auto& instruction) {
        return instruction.opcode == 0x71U &&
               instruction.code_units.size() >= 2U &&
               instruction.code_units[1U] == helper_method_index;
    };
    for (const auto& region : code.tries) {
        assert(std::any_of(
            code.instructions.begin(), code.instructions.end(),
            [&](const auto& instruction) {
                return instruction.offset >= region.start_address &&
                       instruction.offset < region.start_address +
                           region.instruction_count &&
                       is_helper_invoke(instruction);
            }));
        for (const auto& handler : region.handlers) {
            const auto handler_instruction = std::find_if(
                code.instructions.begin(), code.instructions.end(),
                [&](const auto& instruction) {
                    return instruction.offset == handler.address;
                });
            assert(handler_instruction != code.instructions.end());
            assert(handler_instruction->opcode == 0x0dU);
            const auto call = std::next(handler_instruction);
            assert(call != code.instructions.end() && is_helper_invoke(*call));
        }
    }
    bool found_shared_handler = false;
    for (std::size_t first = 0U; first < code.tries.size(); ++first) {
        for (std::size_t second = first + 1U; second < code.tries.size();
             ++second) {
            for (const auto& left : code.tries[first].handlers) {
                found_shared_handler = found_shared_handler || std::any_of(
                    code.tries[second].handlers.begin(),
                    code.tries[second].handlers.end(),
                    [&](const auto& right) {
                        return left.address == right.address;
                    });
            }
        }
    }
    assert(found_shared_handler);
    const auto helper_owner = output.descriptor(helper_method->class_idx);
    assert(helper_owner != "Llowering/Business;");
    const auto helper_class = std::find_if(
        output.classes().begin(), output.classes().end(), [&](const auto& item) {
            return output.descriptor(item.class_idx) == helper_owner;
        });
    assert(helper_class != output.classes().end());
    const auto helper_class_index = static_cast<std::size_t>(
        std::distance(output.classes().begin(), helper_class));
    const auto helper_code = birch::dex::DecodeCodeItem(
        output,
        output.class_data(helper_class_index).direct_methods.front().code_off);
    assert(std::none_of(
        helper_code.instructions.begin(), helper_code.instructions.end(),
        [](const auto& instruction) {
            return instruction.kind != birch::dex::InstructionKind::Payload &&
                   instruction.opcode == 0x00U;
        }));
    const auto ir = birch::dex::BuildMethodIr(code);
    assert(birch::dex::ControlFlowGraph(ir).Verify());
    if (const auto* path = std::getenv("BIRCH_LOWERING_OUTPUT")) {
        std::ofstream stream(path, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(lowered.bytes.data()),
                     static_cast<std::streamsize>(lowered.bytes.size()));
    }

    birch::dex::DexBuilder reorder_builder(38U);
    birch::dex::ClassSpec reorder_class;
    reorder_class.descriptor = "Llowering/Reorder;";
    birch::dex::MethodSpec reorder_method;
    reorder_method.name = "execute";
    reorder_method.access_flags = 0x0001U;
    reorder_method.body.registers_size = 2U;
    reorder_method.body.ins_size = 1U;
    reorder_method.body.code_units = {
        0x0138U, 7U,       // if-eqz p0(v1), branch-chain
        0x1112U,           // fallthrough chain
        0x0029U, 7U,       // goto/16 return
        0x2112U, 0x000eU,  // disconnected legal block
        0x3112U,           // branch chain
        0x0029U, 2U,       // goto/16 return
        0x000eU,
    };
    reorder_class.virtual_methods.push_back(std::move(reorder_method));
    reorder_builder.AddClass(std::move(reorder_class));
    const auto reorder_source = birch::dex::DexFile::Parse(reorder_builder.Build());
    const auto reorder_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 9981,
      "scope": {"protect": [{"pattern": "Llowering/Reorder;"}], "keep": []},
      "passes": {
        "anti_analysis.debug_info_removal": {"enabled": false, "intensity": 1.0},
        "cfg.block_reordering": {"enabled": true, "intensity": 1.0}
      }
    })json");
    const auto reordered = birch::guard::DexCodeLowering(reorder_config).Apply(
        reorder_source);
    const auto reorder_output = birch::dex::DexFile::Parse(reordered.bytes);
    const auto original_code = birch::dex::DecodeCodeItem(
        reorder_source,
        reorder_source.class_data(0U).virtual_methods.front().code_off);
    const auto reordered_code = birch::dex::DecodeCodeItem(
        reorder_output,
        reorder_output.class_data(0U).virtual_methods.front().code_off);
    assert(reordered_code.insns != original_code.insns);
    assert(birch::dex::ControlFlowGraph(
        birch::dex::BuildMethodIr(reordered_code)).Verify());

    birch::dex::DexBuilder data_builder(38U);
    birch::dex::ClassSpec data_class;
    data_class.descriptor = "Llowering/Data;";
    birch::dex::MethodSpec data_method;
    data_method.name = "value";
    data_method.return_type = "I";
    data_method.body.registers_size = 1U;
    data_method.body.code_units = {0x1012U, 0x000fU};
    data_class.direct_methods.push_back(std::move(data_method));
    data_builder.AddClass(std::move(data_class));
    const auto data_source = birch::dex::DexFile::Parse(data_builder.Build());
    const auto data_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 7654321,
      "scope": {"protect": [{"pattern": "Llowering/Data;"}], "keep": []},
      "budget": {"max_method_growth_ratio": 128.0},
      "passes": {
        "anti_analysis.debug_info_removal": {"enabled": false, "intensity": 1.0},
        "strength.per_method_randomization": {"enabled": false, "intensity": 1.0},
        "strength.build_parameter_randomization": {"enabled": false, "intensity": 1.0},
        "data.constant_splitting": {"enabled": true, "intensity": 1.0,
                                     "max_applications_per_method": 1},
        "data.boolean_arithmetic": {"enabled": true, "intensity": 1.0,
                                     "max_applications_per_method": 1},
        "anti_analysis.constant_barriers": {"enabled": true, "intensity": 1.0,
                                            "max_applications_per_method": 1},
        "anti_analysis.instruction_patterns": {"enabled": true, "intensity": 1.0,
                                                "max_applications_per_method": 1}
      }
    })json");
    const auto data_model = birch::guard::DexModelLowering(data_config).Apply(
        data_source);
    const auto data_with_runtime = birch::dex::DexFile::Parse(data_model.bytes);
    const auto data_lowered = birch::guard::DexCodeLowering(data_config).Apply(
        data_with_runtime);
    assert(data_lowered.data_methods == 1U);
    assert(data_lowered.constants_rewritten == 1U);
    // Runtime constant helpers are generated inside the protected closure and
    // must participate in instruction/control hardening as well.
    assert(data_lowered.cfg_methods != 0U);
    assert(data_lowered.pass_applications.at(
        "anti_analysis.instruction_patterns") >= 1U);
    const auto data_output = birch::dex::DexFile::Parse(data_lowered.bytes);
    birch::dex::VerifyDexOrThrow(data_output,
                                 birch::dex::VerificationLevel::Full);
    std::optional<std::uint32_t> data_code_offset;
    for (std::size_t class_index = 0U;
         class_index < data_output.classes().size(); ++class_index) {
        if (data_output.descriptor(
                data_output.classes()[class_index].class_idx) !=
            "Llowering/Data;") {
            continue;
        }
        const auto& class_data = data_output.class_data(class_index);
        const auto method = std::find_if(
            class_data.direct_methods.begin(), class_data.direct_methods.end(),
            [&](const auto& encoded) {
                return data_output.string(
                    data_output.methods().at(encoded.method_idx).name_idx) ==
                    "value";
            });
        assert(method != class_data.direct_methods.end());
        data_code_offset = method->code_off;
    }
    assert(data_code_offset.has_value());
    const auto data_code = birch::dex::DecodeCodeItem(
        data_output, *data_code_offset);
    assert(data_code.instructions.back().opcode == 0x0fU);
    const auto encoded_constant = std::find_if(
        data_code.instructions.begin(), data_code.instructions.end(),
        [](const auto& instruction) { return instruction.opcode == 0x14U; });
    assert(encoded_constant != data_code.instructions.end());
    std::uint32_t computed = static_cast<std::uint32_t>(
        encoded_constant->code_units.at(1U)) |
        static_cast<std::uint32_t>(
            encoded_constant->code_units.at(2U)) << 16U;
    bool found_runtime_barrier = false;
    for (auto iterator = std::next(encoded_constant);
         iterator != data_code.instructions.end(); ++iterator) {
        const auto& instruction = *iterator;
        if (instruction.opcode == 0xd7U || instruction.opcode == 0xd0U) {
            const auto literal = static_cast<std::uint32_t>(
                static_cast<std::int32_t>(static_cast<std::int16_t>(
                    instruction.code_units.at(1U))));
            if (instruction.opcode == 0xd7U) computed ^= literal;
            else computed += literal;
        } else if (instruction.opcode == 0x71U) {
            const auto& target = data_output.methods().at(
                instruction.code_units.at(1U));
            found_runtime_barrier = data_output.string(target.name_idx) ==
                birch::guard::RuntimeConstantMethodName(7654321U);
        }
    }
    assert(computed == 1U);
    assert(found_runtime_barrier);
    assert(data_code.outs_size >= 1U);
    bool found_constant_helper = false;
    for (std::size_t class_index = 0U;
         class_index < data_output.classes().size(); ++class_index) {
        const auto& class_data = data_output.class_data(class_index);
        for (const auto& encoded : class_data.direct_methods) {
            const auto& id = data_output.methods().at(encoded.method_idx);
            if (data_output.string(id.name_idx) !=
                birch::guard::RuntimeConstantMethodName(7654321U)) {
                continue;
            }
            found_constant_helper = true;
            assert((encoded.access_flags & 0x0020U) != 0U);
            assert(std::count_if(
                class_data.static_fields.begin(),
                class_data.static_fields.end(), [&](const auto& field) {
                    return data_output.descriptor(
                        data_output.fields().at(field.field_idx).type_idx) == "I";
                }) == 2U);
            const auto helper_code = birch::dex::DecodeCodeItem(
                data_output, encoded.code_off);
            bool saw_runtime_identity = false;
            bool runtime_identity_uses_v3 = false;
            bool saw_identity_mix = false;
            bool saw_recursive_barrier_call = false;
            for (const auto& instruction : helper_code.instructions) {
                if (instruction.opcode == 0x71U) {
                    saw_recursive_barrier_call =
                        saw_recursive_barrier_call ||
                        (instruction.code_units.size() >= 2U &&
                         instruction.code_units[1U] == helper_method_index);
                    const auto& target = data_output.methods().at(
                        instruction.code_units.at(1U));
                    const auto is_identity =
                        data_output.descriptor(target.class_idx) ==
                            "Ljava/lang/System;" &&
                        data_output.string(target.name_idx) ==
                            "identityHashCode";
                    saw_runtime_identity = saw_runtime_identity || is_identity;
                    runtime_identity_uses_v3 =
                        runtime_identity_uses_v3 ||
                        (is_identity && instruction.code_units.size() == 3U &&
                         (instruction.code_units.front() >> 12U) == 1U &&
                         (instruction.code_units[2U] & 0x0fU) == 3U);
                }
                saw_identity_mix = saw_identity_mix ||
                    (instruction.opcode == 0xb7U &&
                     instruction.code_units.front() == 0x32b7U);
            }
            assert(saw_runtime_identity && runtime_identity_uses_v3 &&
                   saw_identity_mix && !saw_recursive_barrier_call);
            assert(std::count_if(
                helper_code.instructions.begin(), helper_code.instructions.end(),
                [](const auto& instruction) {
                    return instruction.opcode == 0x60U;
                }) == 2);
            assert(std::count_if(
                helper_code.instructions.begin(), helper_code.instructions.end(),
                [](const auto& instruction) {
                    return instruction.opcode == 0x67U;
                }) == 2);
        }
    }
    assert(found_constant_helper);
    if (const auto* path = std::getenv("BIRCH_DATA_LOWERING_OUTPUT")) {
        std::ofstream stream(path, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(data_lowered.bytes.data()),
                     static_cast<std::streamsize>(data_lowered.bytes.size()));
    }

    birch::dex::DexBuilder opaque_builder(38U);
    birch::dex::ClassSpec opaque_class;
    opaque_class.descriptor = "Llowering/Opaque;";
    birch::dex::MethodSpec opaque_method;
    opaque_method.name = "value";
    opaque_method.return_type = "I";
    opaque_method.body.registers_size = 2U;
    opaque_method.body.code_units = {0x1012U, 0x000fU};
    opaque_class.direct_methods.push_back(std::move(opaque_method));
    opaque_builder.AddClass(std::move(opaque_class));
    const auto opaque_source = birch::dex::DexFile::Parse(opaque_builder.Build());
    const auto opaque_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 991177,
      "scope": {"protect": [{"pattern": "Llowering/Opaque;"}], "keep": []},
      "budget": {"max_method_growth_ratio": 512.0},
      "passes": {
        "anti_analysis.debug_info_removal": {"enabled": false, "intensity": 1.0},
        "predicate.number_theory": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.polynomial": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.matrix": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.bitwise": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.cross_process": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.cross_class_state": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.history": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.overflow": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.floating_point": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.hash_collision": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.crypto": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.graph_problem": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.class_loading_state": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1},
        "predicate.reference_identity": {"enabled": true, "intensity": 1.0, "max_applications_per_method": 1}
      }
    })json");
    const auto opaque_model = birch::guard::DexModelLowering(opaque_config).Apply(
        opaque_source);
    const auto opaque_with_runtime = birch::dex::DexFile::Parse(opaque_model.bytes);
    assert(opaque_with_runtime.classes().size() == 3U);
    const auto opaque_lowered = birch::guard::DexCodeLowering(opaque_config).Apply(
        opaque_with_runtime);
    assert(opaque_lowered.cfg_methods == 1U);
    for (const auto id : birch::guard::kRuntimeOpaquePasses) {
        assert(opaque_lowered.pass_applications.at(std::string(id)) == 1U);
    }
    const auto opaque_output = birch::dex::DexFile::Parse(opaque_lowered.bytes);
    birch::dex::VerifyDexOrThrow(opaque_output,
                                 birch::dex::VerificationLevel::Full);
    std::size_t helper_methods = 0U;
    std::size_t helper_classes = 0U;
    std::size_t helper_fields = 0U;
    std::size_t strategy_methods = 0U;
    std::set<std::vector<std::uint16_t>> strategy_fingerprints;
    bool cross_method_call = false;
    bool cross_class_read = false;
    bool protected_has_runtime_calls = false;
    for (std::size_t class_index = 0U;
         class_index < opaque_output.classes().size(); ++class_index) {
        const auto descriptor = opaque_output.descriptor(
            opaque_output.classes()[class_index].class_idx);
        const auto& class_data = opaque_output.class_data(class_index);
        bool helper_class = false;
        for (std::size_t strategy = 0U;
             strategy < birch::guard::kRuntimeOpaquePasses.size(); ++strategy) {
            const auto expected_name =
                birch::guard::RuntimeOpaqueMethodName(991177U, strategy);
            helper_class |= std::any_of(
                class_data.direct_methods.begin(),
                class_data.direct_methods.end(), [&](const auto& encoded) {
                    const auto& method =
                        opaque_output.methods().at(encoded.method_idx);
                    return opaque_output.string(method.name_idx) == expected_name;
                });
        }
        if (helper_class) {
            ++helper_classes;
            helper_methods += class_data.direct_methods.size();
            helper_fields += class_data.static_fields.size();
            assert(descriptor.find("birch") == std::string::npos);
            assert(descriptor.find("Opaque") == std::string::npos);
            for (const auto& encoded : class_data.direct_methods) {
                const auto method_name = opaque_output.string(
                    opaque_output.methods().at(encoded.method_idx).name_idx);
                std::optional<std::size_t> strategy_index;
                for (std::size_t strategy = 0U;
                     strategy < birch::guard::kRuntimeOpaquePasses.size();
                     ++strategy) {
                    if (method_name == birch::guard::RuntimeOpaqueMethodName(
                            991177U, strategy)) {
                        strategy_index = strategy;
                        break;
                    }
                }
                if (!strategy_index.has_value()) continue;
                const auto helper_code = birch::dex::DecodeCodeItem(
                    opaque_output, encoded.code_off);
                ++strategy_methods;
                strategy_fingerprints.insert(helper_code.insns);
                bool saw_runtime_identity = false;
                bool runtime_identity_uses_v2 = false;
                bool saw_identity_mix = false;
                for (const auto& instruction : helper_code.instructions) {
                    if (instruction.opcode == 0x71U) {
                        const auto& target = opaque_output.methods().at(
                            instruction.code_units.at(1U));
                        const auto is_identity =
                            opaque_output.descriptor(target.class_idx) ==
                                "Ljava/lang/System;" &&
                            opaque_output.string(target.name_idx) ==
                                "identityHashCode";
                        saw_runtime_identity = saw_runtime_identity || is_identity;
                        runtime_identity_uses_v2 =
                            runtime_identity_uses_v2 ||
                            (is_identity &&
                             instruction.code_units.size() == 3U &&
                             (instruction.code_units.front() >> 12U) == 1U &&
                             (instruction.code_units[2U] & 0x0fU) == 2U);
                    }
                    saw_identity_mix = saw_identity_mix ||
                        (instruction.opcode == 0xb7U &&
                         instruction.code_units.front() == 0x50b7U);
                }
                assert(saw_runtime_identity && runtime_identity_uses_v2 &&
                       saw_identity_mix);
                assert(std::count_if(
                    helper_code.instructions.begin(),
                    helper_code.instructions.end(),
                    [](const auto& instruction) {
                        return instruction.opcode == 0x60U;
                    }) >= 4);
                assert(std::count_if(
                    helper_code.instructions.begin(),
                    helper_code.instructions.end(),
                    [](const auto& instruction) {
                        return instruction.opcode == 0x67U;
                    }) == 2);
                assert(std::none_of(
                    helper_code.instructions.begin(),
                    helper_code.instructions.end(),
                    [](const auto& instruction) {
                        return instruction.code_units.size() == 2U &&
                               instruction.code_units[0U] == 0x01dfU &&
                               instruction.code_units[1U] == 0xff00U;
                    }));
                for (const auto& instruction : helper_code.instructions) {
                    if (*strategy_index == 4U &&
                        instruction.opcode == 0x71U) {
                        const auto& target = opaque_output.methods().at(
                            instruction.code_units.at(1U));
                        cross_method_call = cross_method_call ||
                            opaque_output.string(target.name_idx) ==
                                birch::guard::RuntimeOpaqueMethodName(
                                    991177U,
                                    birch::guard::kRuntimeOpaquePasses.size());
                    }
                    if (*strategy_index == 5U &&
                        instruction.opcode == 0x60U) {
                        const auto& field = opaque_output.fields().at(
                            instruction.code_units.at(1U));
                        cross_class_read = cross_class_read ||
                            opaque_output.descriptor(field.class_idx) !=
                                descriptor;
                    }
                }
            }
            continue;
        }
        const auto protected_code = birch::dex::DecodeCodeItem(
            opaque_output, class_data.direct_methods.front().code_off);
        protected_has_runtime_calls = std::count_if(
            protected_code.instructions.begin(), protected_code.instructions.end(),
            [](const auto& instruction) {
                return instruction.opcode == 0x71U;
            }) == static_cast<std::ptrdiff_t>(
                birch::guard::kRuntimeOpaquePasses.size());
    }
    for (std::uint32_t string_index = 0U;
         string_index < opaque_output.strings().size(); ++string_index) {
        const auto value = opaque_output.string(string_index);
        assert(value.find("birch/guard/Opaque") == std::string::npos);
        assert(value.find("Opaque$") == std::string::npos);
        assert(value != "FB");
        assert(value != "Ea");
    }
    assert(helper_classes == birch::guard::kRuntimeOpaqueClassShards);
    assert(helper_methods == birch::guard::kRuntimeOpaquePasses.size() + 1U);
    assert(strategy_methods == birch::guard::kRuntimeOpaquePasses.size());
    assert(strategy_fingerprints.size() ==
           birch::guard::kRuntimeOpaquePasses.size());
    assert(helper_fields == birch::guard::kRuntimeOpaqueClassShards *
                                birch::guard::kRuntimeOpaqueStateFields);
    assert(cross_method_call && cross_class_read);
    assert(protected_has_runtime_calls);
    if (const auto* path = std::getenv("BIRCH_OPAQUE_LOWERING_OUTPUT")) {
        std::ofstream stream(path, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(opaque_lowered.bytes.data()),
                     static_cast<std::streamsize>(opaque_lowered.bytes.size()));
    }

    // Low-level lowering is intentionally usable without a preceding model
    // pass.  Enabling a runtime predicate on a bare DEX must therefore fall
    // back to a legal local branch instead of requiring an injected helper.
    birch::dex::DexBuilder fallback_builder(38U);
    birch::dex::ClassSpec fallback_class;
    fallback_class.descriptor = "Llowering/Fallback;";
    birch::dex::MethodSpec fallback_method;
    fallback_method.name = "value";
    fallback_method.return_type = "I";
    fallback_method.parameter_types = {"I"};
    fallback_method.access_flags = 0x0009U; // public static
    fallback_method.body.registers_size = 2U;
    fallback_method.body.ins_size = 1U;
    fallback_method.body.code_units = {0x010fU}; // return v1
    fallback_class.direct_methods.push_back(std::move(fallback_method));
    fallback_builder.AddClass(std::move(fallback_class));
    const auto fallback_source = birch::dex::DexFile::Parse(
        fallback_builder.Build());
    const auto fallback_config = birch::guard::GuardConfig::Parse(R"json({
      "scope": {"protect": [{"pattern": "Llowering/Fallback;"}], "keep": []},
      "budget": {"max_method_growth_ratio": 32.0},
      "passes": {
        "anti_analysis.debug_info_removal": {"enabled": false, "intensity": 1.0},
        "cfg.bogus_edges": {"enabled": true, "intensity": 1.0,
                              "max_applications_per_method": 1}
      }
    })json");
    const auto fallback_lowered = birch::guard::DexCodeLowering(
        fallback_config).Apply(fallback_source);
    assert(fallback_lowered.cfg_methods == 0U);
    const auto fallback_output = birch::dex::DexFile::Parse(
        fallback_lowered.bytes);
    birch::dex::VerifyDexOrThrow(fallback_output,
                                 birch::dex::VerificationLevel::Full);
    const auto fallback_code = birch::dex::DecodeCodeItem(
        fallback_output,
        fallback_output.class_data(0U).direct_methods.front().code_off);
    assert(!fallback_code.instructions.empty());
    assert(fallback_code.instructions.front().opcode == 0x0fU);
    assert(fallback_lowered.pass_applications.at("cfg.bogus_edges") == 0U);

    // Structural acceptance for real basic-block flattening. The original
    // method has four executable blocks and direct conditional/goto edges.
    // The initial dispatcher has distinct entry/invalid-state gates. Original
    // business successors must be reached by typed switch cases, never by the
    // old direct edges. An invalid gate may also be a typed switch default;
    // it no longer needs a redundant private goto island for each caller.
    birch::dex::DexBuilder cff_builder(38U);
    birch::dex::ClassSpec cff_class;
    cff_class.descriptor = "Llowering/RealCff;";
    birch::dex::MethodSpec cff_method;
    cff_method.name = "choose";
    cff_method.return_type = "I";
    cff_method.parameter_types = {"I"};
    cff_method.access_flags = 0x0009U; // public static
    cff_method.body.registers_size = 2U;
    cff_method.body.ins_size = 1U;
    cff_method.body.code_units = {
        0x0138U, 5U,       // if-eqz v1, true-case
        0x1012U,           // const/4 v0, #1
        0x0029U, 3U,       // goto/16 return
        0x2012U,           // const/4 v0, #2
        0x000fU,           // return v0
    };
    cff_class.direct_methods.push_back(std::move(cff_method));
    cff_builder.AddClass(std::move(cff_class));
    const auto cff_source = birch::dex::DexFile::Parse(cff_builder.Build());
    const auto source_cff_code = birch::dex::DecodeCodeItem(
        cff_source, cff_source.class_data(0U).direct_methods.front().code_off);
    const auto source_cff_blocks =
        birch::dex::BuildMethodIr(source_cff_code).blocks().size();
    assert(source_cff_blocks == 4U);
    const auto verify_choose = [&](const birch::dex::CodeItem& transformed) {
        for (const auto input : {0U, 1U, 2U, 16U, 0x7fffffffU, 0x80000000U, 0xffffffffU}) {
            const std::array arguments{input};
            const auto expected = input == 0U ? 2U : 1U;
            assert(birch::test::IntDexInterpreter::Execute(source_cff_code, arguments) == expected);
            assert(birch::test::IntDexInterpreter::Execute(transformed, arguments) == expected);
        }
    };
    const auto cff_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 881726,
      "scope": {"protect": [{"pattern": "Llowering/RealCff;"}], "keep": []},
      "budget": {"max_method_growth_ratio": 512.0},
      "passes": {
        "anti_analysis.debug_info_removal": {"enabled": true, "intensity": 1.0},
        "cfg.flattening": {"enabled": true, "intensity": 1.0,
                             "max_applications_per_method": 1}
      }
    })json");
    const auto cff_lowered = birch::guard::DexCodeLowering(cff_config).Apply(
        cff_source);
    assert(cff_lowered.flattened_methods == 1U);
    const auto cff_output = birch::dex::DexFile::Parse(cff_lowered.bytes);
    birch::dex::VerifyDexOrThrow(cff_output,
                                 birch::dex::VerificationLevel::Full);
    const auto cff_code = birch::dex::DecodeCodeItem(
        cff_output, cff_output.class_data(0U).direct_methods.front().code_off);
    verify_choose(cff_code);
    // State, selector and runtime-call result must not alias: ART merges
    // reference/scalar types at dispatch joins even on contradictory edges.
    if (cff_code.registers_size != 5U) {
        throw std::runtime_error(
            "CFF registers_size mismatch: expected 5, got " +
            std::to_string(cff_code.registers_size));
    }
    const auto dispatcher_instruction = std::find_if(
        cff_code.instructions.begin(), cff_code.instructions.end(),
        [&](const auto& instruction) {
            return instruction.opcode == 0x2cU &&
                   instruction.targets.size() >= source_cff_blocks;
        });
    assert(dispatcher_instruction != cff_code.instructions.end());
    const auto cff_ir = birch::dex::BuildMethodIr(cff_code);
    const birch::dex::ControlFlowGraph cff_graph(cff_ir);
    assert(cff_graph.Verify());
    const auto dispatcher_block = std::find_if(
        cff_ir.blocks().begin(), cff_ir.blocks().end(), [&](const auto& block) {
            return std::any_of(block.instructions.begin(), block.instructions.end(),
                               [&](const auto& instruction) {
                return instruction.dex_offset == dispatcher_instruction->offset;
            });
        });
    assert(dispatcher_block != cff_ir.blocks().end());
    const std::set<std::uint32_t> unique_case_targets(
        dispatcher_instruction->targets.begin(),
        dispatcher_instruction->targets.end());
    assert(unique_case_targets.size() >= source_cff_blocks);
    for (const auto target : dispatcher_instruction->targets) {
        const auto case_block = std::find_if(
            cff_ir.blocks().begin(), cff_ir.blocks().end(),
            [&](const auto& block) { return block.start_offset == target; });
        assert(case_block != cff_ir.blocks().end());
        const auto& predecessors = cff_graph.predecessors().at(case_block->id);
        assert(std::find(predecessors.begin(), predecessors.end(), dispatcher_block->id) !=
               predecessors.end());
        for (const auto predecessor : predecessors) {
            if (predecessor == dispatcher_block->id) continue;
            // Shared invalid-state gates may only gain predecessors from
            // typed-switch default stubs, not from business block shortcuts.
            const auto& default_stub = cff_ir.blocks().at(predecessor);
            assert(default_stub.instructions.size() == 1U);
            assert(default_stub.instructions.front().dex_opcode == 0x2aU);
            assert(case_block->instructions.size() == 1U);
            assert(case_block->instructions.front().dex_opcode == 0x29U);
            const auto& switch_predecessors = cff_graph.predecessors().at(predecessor);
            assert(switch_predecessors.size() == 1U);
            const auto& typed_switch = cff_ir.blocks().at(switch_predecessors.front());
            assert(typed_switch.instructions.back().dex_opcode == 0x2cU);
            assert(std::any_of(typed_switch.successors.begin(), typed_switch.successors.end(),
                [&](const auto& edge) {
                    return edge.target == predecessor &&
                           edge.kind == birch::dex::IrEdgeKind::Fallthrough;
                }));
        }
    }
    // These unique markers identify the three non-entry business blocks.
    // Each original successor must be fed only by real switch cases.
    for (const auto marker : {0x1012U, 0x2012U, 0x000fU}) {
        const auto business_block = std::find_if(cff_ir.blocks().begin(), cff_ir.blocks().end(),
            [&](const auto& block) { return block.instructions.front().encoded.front() == marker; });
        assert(business_block != cff_ir.blocks().end());
        const auto& predecessors = cff_graph.predecessors().at(business_block->id);
        assert(!predecessors.empty());
        for (const auto predecessor : predecessors) {
            const auto& typed_switch = cff_ir.blocks().at(predecessor);
            assert(typed_switch.instructions.back().dex_opcode == 0x2cU);
            assert(std::any_of(typed_switch.successors.begin(), typed_switch.successors.end(),
                [&](const auto& edge) {
                    return edge.target == business_block->id &&
                           edge.kind == birch::dex::IrEdgeKind::SwitchCase;
                }));
        }
    }

    // Nested and multi-state modes must change the full method body, not add
    // independent one-case prefix switches. An outer dispatcher selects one
    // of three inner dispatchers with v3; the inner dispatchers route all four
    // original cases with the independent v2 state.
    auto layered_config = cff_config;
    layered_config.passes.at("cfg.nested_flattening").enabled = true;
    layered_config.passes.at("cfg.nested_flattening").intensity = 1.0;
    layered_config.passes.at("cfg.multi_state_dispatch").enabled = true;
    layered_config.passes.at("cfg.multi_state_dispatch").intensity = 1.0;
    const auto layered_lowered = birch::guard::DexCodeLowering(
        layered_config).Apply(cff_source);
    assert(layered_lowered.flattened_methods == 1U);
    assert(layered_lowered.pass_applications.at("cfg.flattening") == 1U);
    assert(layered_lowered.pass_applications.at("cfg.nested_flattening") == 1U);
    assert(layered_lowered.pass_applications.at("cfg.multi_state_dispatch") == 1U);
    const auto layered_output = birch::dex::DexFile::Parse(
        layered_lowered.bytes);
    birch::dex::VerifyDexOrThrow(layered_output,
                                 birch::dex::VerificationLevel::Full);
    const auto layered_code = birch::dex::DecodeCodeItem(
        layered_output,
        layered_output.class_data(0U).direct_methods.front().code_off);
    verify_choose(layered_code);
    assert(layered_code.registers_size == 7U);
    std::size_t layered_dispatchers = 0U;
    std::size_t maximum_layer_targets = 0U;
    std::size_t total_layer_targets = 0U;
    for (const auto& instruction : layered_code.instructions) {
        if (instruction.opcode != 0x2bU && instruction.opcode != 0x2cU) {
            continue;
        }
        ++layered_dispatchers;
        maximum_layer_targets = std::max(
            maximum_layer_targets, instruction.targets.size());
        total_layer_targets += instruction.targets.size();
    }
    assert(layered_dispatchers >= 4U);
    assert(maximum_layer_targets >= source_cff_blocks);
    assert(total_layer_targets >= source_cff_blocks * 3U);
    assert(std::count_if(
               layered_code.instructions.begin(),
               layered_code.instructions.end(), [](const auto& instruction) {
                   const auto destination = instruction.opcode == 0xb7U ?
                       (instruction.code_units.front() >> 8U) & 15U :
                       instruction.code_units.front() >> 8U;
                   return (instruction.opcode == 0x97U ||
                           instruction.opcode == 0xb7U) && destination == 5U;
               }) >= 9);

    // Nested-only and multi-state-only are distinct lowerings. Nested mode
    // needs state+selector; multi-state adds an encoded joint token and a
    // fourth scratch register that validates all three values before routing.
    auto nested_only_config = cff_config;
    nested_only_config.passes.at("cfg.flattening").enabled = false;
    nested_only_config.passes.at("cfg.nested_flattening").enabled = true;
    nested_only_config.passes.at("cfg.nested_flattening").intensity = 1.0;
    const auto nested_only_lowered = birch::guard::DexCodeLowering(
        nested_only_config).Apply(cff_source);
    const auto nested_only_output = birch::dex::DexFile::Parse(
        nested_only_lowered.bytes);
    birch::dex::VerifyDexOrThrow(nested_only_output,
                                 birch::dex::VerificationLevel::Full);
    const auto nested_only_code = birch::dex::DecodeCodeItem(
        nested_only_output,
        nested_only_output.class_data(0U).direct_methods.front().code_off);
    verify_choose(nested_only_code);
    assert(nested_only_code.registers_size == 5U);
    assert(nested_only_lowered.pass_applications.at(
               "cfg.nested_flattening") == 1U);
    assert(nested_only_lowered.pass_applications.at(
               "cfg.multi_state_dispatch") == 0U);

    auto multi_only_config = cff_config;
    multi_only_config.passes.at("cfg.flattening").enabled = false;
    multi_only_config.passes.at("cfg.multi_state_dispatch").enabled = true;
    multi_only_config.passes.at("cfg.multi_state_dispatch").intensity = 1.0;
    const auto multi_only_lowered = birch::guard::DexCodeLowering(
        multi_only_config).Apply(cff_source);
    const auto multi_only_output = birch::dex::DexFile::Parse(
        multi_only_lowered.bytes);
    birch::dex::VerifyDexOrThrow(multi_only_output,
                                 birch::dex::VerificationLevel::Full);
    const auto multi_only_code = birch::dex::DecodeCodeItem(
        multi_only_output,
        multi_only_output.class_data(0U).direct_methods.front().code_off);
    verify_choose(multi_only_code);
    assert(multi_only_code.registers_size == 7U);
    assert(multi_only_lowered.pass_applications.at(
               "cfg.multi_state_dispatch") == 1U);
    assert(multi_only_lowered.pass_applications.at(
               "cfg.nested_flattening") == 0U);
    assert(multi_only_code.insns != nested_only_code.insns);

    // Table dispatch alone must replace the method with a packed dispatcher
    // whose cases are the original basic blocks.
    auto table_config = cff_config;
    table_config.passes.at("cfg.flattening").enabled = false;
    table_config.passes.at("cfg.table_dispatch").enabled = true;
    table_config.passes.at("cfg.table_dispatch").intensity = 1.0;
    const auto table_lowered = birch::guard::DexCodeLowering(
        table_config).Apply(cff_source);
    assert(table_lowered.flattened_methods == 1U);
    assert(table_lowered.pass_applications.at("cfg.flattening") == 0U);
    assert(table_lowered.pass_applications.at("cfg.table_dispatch") == 1U);
    const auto table_output = birch::dex::DexFile::Parse(table_lowered.bytes);
    birch::dex::VerifyDexOrThrow(table_output,
                                 birch::dex::VerificationLevel::Full);
    const auto table_code = birch::dex::DecodeCodeItem(
        table_output,
        table_output.class_data(0U).direct_methods.front().code_off);
    verify_choose(table_code);
    assert(std::any_of(table_code.instructions.begin(),
                       table_code.instructions.end(), [&](const auto& item) {
        return item.opcode == 0x2bU &&
               item.targets.size() == source_cff_blocks;
    }));
    // Auxiliary sparse gates may coexist with the packed primary table; the
    // packed dispatcher itself remains mandatory.

    // Indirect dispatch alone uses non-contiguous encoded states and a sparse
    // dispatcher over the original blocks.
    auto indirect_config = cff_config;
    indirect_config.passes.at("cfg.flattening").enabled = false;
    indirect_config.passes.at("cfg.indirect_dispatch").enabled = true;
    indirect_config.passes.at("cfg.indirect_dispatch").intensity = 1.0;
    const auto indirect_lowered = birch::guard::DexCodeLowering(
        indirect_config).Apply(cff_source);
    assert(indirect_lowered.flattened_methods == 1U);
    assert(indirect_lowered.pass_applications.at("cfg.indirect_dispatch") == 1U);
    const auto indirect_output = birch::dex::DexFile::Parse(
        indirect_lowered.bytes);
    birch::dex::VerifyDexOrThrow(indirect_output,
                                 birch::dex::VerificationLevel::Full);
    const auto indirect_code = birch::dex::DecodeCodeItem(
        indirect_output,
        indirect_output.class_data(0U).direct_methods.front().code_off);
    verify_choose(indirect_code);
    assert(std::any_of(indirect_code.instructions.begin(),
                       indirect_code.instructions.end(), [&](const auto& item) {
        return item.opcode == 0x2cU &&
               item.targets.size() == source_cff_blocks;
    }));

    // Conditional hardening is lowered inside the real state machine. At full
    // intensity the dispatcher contains sixteen independently encoded decoy
    // states, and contradictory rechecks of the original condition enter them.
    auto hardened_branch_config = cff_config;
    hardened_branch_config.passes.at("cfg.flattening").enabled = false;
    for (const auto* id : {"cfg.condition_expansion",
                           "cfg.conditional_nesting", "cfg.bogus_edges",
                           "cfg.dead_blocks",
                           "anti_analysis.path_explosion"}) {
        hardened_branch_config.passes.at(id).enabled = true;
        hardened_branch_config.passes.at(id).intensity = 1.0;
    }
    const auto hardened_branch_lowered = birch::guard::DexCodeLowering(
        hardened_branch_config).Apply(cff_source);
    assert(hardened_branch_lowered.flattened_methods == 1U);
    assert(hardened_branch_lowered.pass_applications.at(
               "cfg.condition_expansion") == 1U);
    assert(hardened_branch_lowered.pass_applications.at(
               "cfg.conditional_nesting") == 1U);
    assert(hardened_branch_lowered.pass_applications.at(
               "cfg.bogus_edges") == 1U);
    assert(hardened_branch_lowered.pass_applications.at(
               "cfg.dead_blocks") >= 16U);
    assert(hardened_branch_lowered.pass_applications.at(
               "anti_analysis.path_explosion") == 1U);
    const auto hardened_branch_output = birch::dex::DexFile::Parse(
        hardened_branch_lowered.bytes);
    birch::dex::VerifyDexOrThrow(hardened_branch_output,
                                 birch::dex::VerificationLevel::Full);
    const auto hardened_branch_code = birch::dex::DecodeCodeItem(
        hardened_branch_output,
        hardened_branch_output.class_data(0U).direct_methods.front().code_off);
    assert(std::any_of(hardened_branch_code.instructions.begin(),
        hardened_branch_code.instructions.end(),
                       [&](const auto& item) {
        return (item.opcode == 0x2bU || item.opcode == 0x2cU) &&
               item.targets.size() >= source_cff_blocks + 16U;
    }));
    assert(std::count_if(
               hardened_branch_code.instructions.begin(),
               hardened_branch_code.instructions.end(),
               [](const auto& item) {
                   return item.kind ==
                       birch::dex::InstructionKind::ConditionalBranch;
               }) >= 10);

    auto expansion_only_config = cff_config;
    expansion_only_config.passes.at("cfg.flattening").enabled = false;
    expansion_only_config.passes.at("cfg.condition_expansion").enabled = true;
    expansion_only_config.passes.at("cfg.condition_expansion").intensity = 1.0;
    const auto expansion_only = birch::guard::DexCodeLowering(
        expansion_only_config).Apply(cff_source);
    const auto expansion_only_dex = birch::dex::DexFile::Parse(
        expansion_only.bytes);
    birch::dex::VerifyDexOrThrow(expansion_only_dex,
                                 birch::dex::VerificationLevel::Full);
    const auto expansion_only_code = birch::dex::DecodeCodeItem(
        expansion_only_dex,
        expansion_only_dex.class_data(0U).direct_methods.front().code_off);

    auto nesting_only_config = cff_config;
    nesting_only_config.passes.at("cfg.flattening").enabled = false;
    nesting_only_config.passes.at("cfg.conditional_nesting").enabled = true;
    nesting_only_config.passes.at("cfg.conditional_nesting").intensity = 1.0;
    const auto nesting_only = birch::guard::DexCodeLowering(
        nesting_only_config).Apply(cff_source);
    const auto nesting_only_dex = birch::dex::DexFile::Parse(
        nesting_only.bytes);
    birch::dex::VerifyDexOrThrow(nesting_only_dex,
                                 birch::dex::VerificationLevel::Full);
    const auto nesting_only_code = birch::dex::DecodeCodeItem(
        nesting_only_dex,
        nesting_only_dex.class_data(0U).direct_methods.front().code_off);
    const auto branch_count = [](const auto& item) {
        return std::count_if(
            item.instructions.begin(), item.instructions.end(),
            [](const auto& instruction) {
                return instruction.kind ==
                    birch::dex::InstructionKind::ConditionalBranch;
            });
    };
    assert(branch_count(nesting_only_code) >
           branch_count(expansion_only_code));
    assert(nesting_only_code.insns != expansion_only_code.insns);

    // Mixed PS/SS/IF is a real two-level dispatcher: packed outer routing,
    // sparse inner routing, and a per-bucket state check before case dispatch.
    auto mixed_config = cff_config;
    mixed_config.passes.at("cfg.flattening").enabled = false;
    mixed_config.passes.at("cfg.mixed_ps_ss_if").enabled = true;
    mixed_config.passes.at("cfg.mixed_ps_ss_if").intensity = 1.0;
    const auto mixed_lowered = birch::guard::DexCodeLowering(
        mixed_config).Apply(cff_source);
    assert(mixed_lowered.flattened_methods == 1U);
    assert(mixed_lowered.pass_applications.at("cfg.mixed_ps_ss_if") == 1U);
    const auto mixed_output = birch::dex::DexFile::Parse(mixed_lowered.bytes);
    birch::dex::VerifyDexOrThrow(mixed_output,
                                 birch::dex::VerificationLevel::Full);
    const auto mixed_code = birch::dex::DecodeCodeItem(
        mixed_output,
        mixed_output.class_data(0U).direct_methods.front().code_off);
    assert(mixed_code.registers_size == 6U); // includes independent call-result scratch
    assert(std::any_of(mixed_code.instructions.begin(),
                       mixed_code.instructions.end(), [](const auto& item) {
        return item.opcode == 0x2bU;
    }));
    assert(std::any_of(mixed_code.instructions.begin(),
                       mixed_code.instructions.end(), [](const auto& item) {
        return item.opcode == 0x2cU;
    }));
    assert(std::any_of(mixed_code.instructions.begin(),
                       mixed_code.instructions.end(), [](const auto& item) {
        return item.kind == birch::dex::InstructionKind::ConditionalBranch;
    }));
    assert(std::any_of(mixed_code.instructions.begin(),
                       mixed_code.instructions.end(), [](const auto& item) {
        return item.opcode == 0x2aU;
    }));

    // Dalvik has no Kotlin coroutine ABI requirement here. The callback pass
    // lowers to an equivalent continuation state machine that routes every
    // original block through two independent state variables and a stateful
    // cross-class continuation helper.
    auto callback_config = cff_config;
    callback_config.passes.at("cfg.flattening").enabled = false;
    callback_config.passes.at("cfg.callback_style").enabled = true;
    callback_config.passes.at("cfg.callback_style").intensity = 1.0;
    const auto callback_modeled = birch::guard::DexModelLowering(
        callback_config).Apply(cff_source);
    const auto callback_source = birch::dex::DexFile::Parse(
        callback_modeled.bytes);
    const auto callback_lowered = birch::guard::DexCodeLowering(
        callback_config).Apply(callback_source);
    assert(callback_lowered.flattened_methods == 1U);
    assert(callback_lowered.pass_applications.at("cfg.callback_style") == 1U);
    const auto callback_output = birch::dex::DexFile::Parse(
        callback_lowered.bytes);
    birch::dex::VerifyDexOrThrow(callback_output,
                                 birch::dex::VerificationLevel::Full);
    const auto callback_business = std::find_if(
        callback_output.classes().begin(), callback_output.classes().end(),
        [&](const auto& item) {
            return callback_output.descriptor(item.class_idx) ==
                   "Llowering/RealCff;";
        });
    assert(callback_business != callback_output.classes().end());
    const auto callback_business_index = static_cast<std::size_t>(
        std::distance(callback_output.classes().begin(), callback_business));
    const auto callback_code = birch::dex::DecodeCodeItem(
        callback_output,
        callback_output.class_data(
            callback_business_index).direct_methods.front().code_off);
    std::set<std::uint16_t> callback_dispatch_registers;
    std::size_t callback_targets = 0U;
    bool callback_cross_class_call = false;
    for (const auto& instruction : callback_code.instructions) {
        if (instruction.opcode == 0x71U) {
            const auto& target = callback_output.methods().at(
                instruction.code_units.at(1U));
            callback_cross_class_call = callback_cross_class_call ||
                callback_output.string(target.name_idx) ==
                    birch::guard::RuntimeExceptionMethodName(
                        callback_config.seed);
        }
        if (instruction.opcode != 0x2bU && instruction.opcode != 0x2cU) {
            continue;
        }
        callback_dispatch_registers.insert(static_cast<std::uint16_t>(
            instruction.code_units.front() >> 8U));
        callback_targets += instruction.targets.size();
    }
    assert(!callback_dispatch_registers.empty());
    assert(callback_targets >= source_cff_blocks + 3U);
    assert(callback_cross_class_call);

    // Loop-state-machine mode lowers an actual back edge through the full
    // dispatcher instead of prepending an unrelated counter loop.
    birch::dex::DexBuilder loop_builder(38U);
    birch::dex::ClassSpec loop_class;
    loop_class.descriptor = "Llowering/Loop;";
    birch::dex::MethodSpec loop_method;
    loop_method.name = "count";
    loop_method.return_type = "I";
    loop_method.parameter_types = {"I"};
    loop_method.access_flags = 0x0009U;
    loop_method.body.registers_size = 2U;
    loop_method.body.ins_size = 1U;
    loop_method.body.code_units = {
        0x0012U,
        0x013dU, 6U,
        0x01d8U, 0xff01U,
        0x0029U, 0xfffcU,
        0x000fU,
    };
    loop_class.direct_methods.push_back(std::move(loop_method));
    loop_builder.AddClass(std::move(loop_class));
    const auto loop_source = birch::dex::DexFile::Parse(loop_builder.Build());
    const auto loop_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 1188,
      "scope": {"protect": [{"pattern": "Llowering/Loop;"}], "keep": []},
      "budget": {"max_method_growth_ratio": 128.0},
      "passes": {
        "anti_analysis.debug_info_removal": {"enabled": false, "intensity": 1.0},
        "cfg.loop_state_machine": {"enabled": true, "intensity": 1.0,
                                      "max_applications_per_method": 1}
      }
    })json");
    const auto loop_lowered = birch::guard::DexCodeLowering(
        loop_config).Apply(loop_source);
    assert(loop_lowered.flattened_methods == 1U);
    assert(loop_lowered.pass_applications.at("cfg.loop_state_machine") == 1U);
    const auto loop_output = birch::dex::DexFile::Parse(loop_lowered.bytes);
    birch::dex::VerifyDexOrThrow(loop_output,
                                 birch::dex::VerificationLevel::Full);
    const auto loop_code = birch::dex::DecodeCodeItem(
        loop_output,
        loop_output.class_data(0U).direct_methods.front().code_off);
    assert(std::any_of(loop_code.instructions.begin(),
                       loop_code.instructions.end(),
                       [](const auto& instruction) {
                           return instruction.opcode == 0x2cU &&
                                  instruction.targets.size() >= 3U;
                       }));

    birch::dex::DexBuilder switch_builder(38U);
    birch::dex::ClassSpec switch_class;
    switch_class.descriptor = "Llowering/SwitchCff;";
    birch::dex::MethodSpec switch_method;
    switch_method.name = "choose";
    switch_method.return_type = "I";
    switch_method.parameter_types = {"I"};
    switch_method.body.registers_size = 2U;
    switch_method.body.ins_size = 1U;
    switch_method.body.code_units = {
        0x012bU, 14U, 0U, // packed-switch v1, payload@14
        0x0012U,          // default: const/4 v0, #0
        0x0029U, 8U,      // goto/16 return@12
        0x1012U,          // case 0: const/4 v0, #1
        0x0029U, 5U,      // goto/16 return@12
        0x2012U,          // case 1: const/4 v0, #2
        0x0029U, 2U,      // goto/16 return@12
        0x000fU, 0x0000U, // return v0; payload alignment
        0x0100U, 2U,      // packed-switch payload, two entries
        0U, 0U,           // first key = 0
        6U, 0U,           // case 0 target relative to switch@0
        9U, 0U,           // case 1 target relative to switch@0
    };
    switch_class.direct_methods.push_back(std::move(switch_method));
    switch_builder.AddClass(std::move(switch_class));
    const auto switch_source = birch::dex::DexFile::Parse(
        switch_builder.Build());
    auto switch_config = cff_config;
    switch_config.scope.protect.front().pattern = "Llowering/SwitchCff;";
    const auto switch_lowered = birch::guard::DexCodeLowering(
        switch_config).Apply(switch_source);
    assert(switch_lowered.flattened_methods == 1U);
    const auto switch_output = birch::dex::DexFile::Parse(
        switch_lowered.bytes);
    birch::dex::VerifyDexOrThrow(switch_output,
                                 birch::dex::VerificationLevel::Full);
    const auto switch_code = birch::dex::DecodeCodeItem(
        switch_output,
        switch_output.class_data(0U).direct_methods.front().code_off);
    assert(std::count_if(
               switch_code.instructions.begin(), switch_code.instructions.end(),
               [](const auto& instruction) {
                   return instruction.kind == birch::dex::InstructionKind::Switch;
               }) >= 2);
    assert(std::none_of(
        switch_code.instructions.begin(), switch_code.instructions.end(),
        [](const auto& instruction) {
            return instruction.kind != birch::dex::InstructionKind::Payload &&
                   instruction.opcode == 0x00U;
        }));

    // fill-array-data payloads are relocated with their 31t displacement so
    // generated string/data helpers do not fall out of full CFF coverage.
    birch::dex::DexBuilder fill_builder(38U);
    birch::dex::ClassSpec fill_class;
    fill_class.descriptor = "Llowering/FillCff;";
    birch::dex::MethodSpec fill_method;
    fill_method.name = "values";
    fill_method.return_type = "[I";
    fill_method.access_flags = 0x0009U;
    fill_method.body.registers_size = 1U;
    fill_method.body.code_units = {
        0x2012U,             // const/4 v0, #2
        0x0023U, 0U,        // new-array v0, v0, [I
        0x0026U, 5U, 0U,    // fill-array-data v0, payload@8
        0x0011U,             // return-object v0
        0x0000U,             // source payload alignment
        0x0300U, 4U, 2U, 0U,
        0x1122U, 0x3344U, 0x5566U, 0x7788U,
    };
    fill_method.body.references.push_back(
        {birch::dex::TypeReference{"[I"}, 2U, false});
    fill_class.direct_methods.push_back(std::move(fill_method));
    fill_builder.AddClass(std::move(fill_class));
    const auto fill_source = birch::dex::DexFile::Parse(fill_builder.Build());
    auto fill_config = cff_config;
    fill_config.scope.protect.front().pattern = "Llowering/FillCff;";
    const auto fill_lowered = birch::guard::DexCodeLowering(
        fill_config).Apply(fill_source);
    assert(fill_lowered.flattened_methods == 1U);
    const auto fill_output = birch::dex::DexFile::Parse(fill_lowered.bytes);
    birch::dex::VerifyDexOrThrow(fill_output,
                                 birch::dex::VerificationLevel::Full);
    const auto fill_code = birch::dex::DecodeCodeItem(
        fill_output, fill_output.class_data(0U).direct_methods.front().code_off);
    assert(std::any_of(fill_code.instructions.begin(),
                       fill_code.instructions.end(), [](const auto& instruction) {
        return instruction.opcode == 0x26U;
    }));
    assert(std::any_of(fill_code.instructions.begin(),
                       fill_code.instructions.end(), [](const auto& instruction) {
        return instruction.kind == birch::dex::InstructionKind::Payload &&
               !instruction.code_units.empty() &&
               instruction.code_units.front() == 0x0300U;
    }));
    assert(std::none_of(fill_code.instructions.begin(),
                        fill_code.instructions.end(), [](const auto& instruction) {
        return instruction.kind != birch::dex::InstructionKind::Payload &&
               instruction.opcode == 0x00U;
    }));

    birch::dex::DexBuilder try_builder(38U);
    birch::dex::ClassSpec try_class;
    try_class.descriptor = "Llowering/TryCff;";
    birch::dex::MethodSpec try_method;
    try_method.name = "divide";
    try_method.return_type = "I";
    try_method.parameter_types = {"I"};
    try_method.body.registers_size = 2U;
    try_method.body.ins_size = 1U;
    try_method.body.code_units = {
        0x1012U, // const/4 v0, #1
        0x10b3U, // div-int/2addr v0, v1
        0x000fU, // return v0
        0x000dU, // handler: move-exception v0
        0xf012U, // const/4 v0, #-1
        0x000fU, // return v0
    };
    try_method.body.try_regions.push_back(
        {0U, 2U, {{std::nullopt, 3U}}});
    try_class.direct_methods.push_back(std::move(try_method));
    try_builder.AddClass(std::move(try_class));
    const auto try_source = birch::dex::DexFile::Parse(try_builder.Build());
    auto try_config = cff_config;
    try_config.scope.protect.front().pattern = "Llowering/TryCff;";
    const auto try_lowered = birch::guard::DexCodeLowering(try_config).Apply(
        try_source);
    assert(try_lowered.flattened_methods == 1U);
    const auto try_output = birch::dex::DexFile::Parse(try_lowered.bytes);
    birch::dex::VerifyDexOrThrow(try_output,
                                 birch::dex::VerificationLevel::Full);
    const auto try_code = birch::dex::DecodeCodeItem(
        try_output, try_output.class_data(0U).direct_methods.front().code_off);
    assert(!try_code.tries.empty());
    const auto handler_address = try_code.tries.front().handlers.front().address;
    const auto handler_instruction = std::find_if(
        try_code.instructions.begin(), try_code.instructions.end(),
        [&](const auto& instruction) {
            return instruction.offset == handler_address;
        });
    assert(handler_instruction != try_code.instructions.end());
    assert(handler_instruction->opcode == 0x0dU);
    for (const auto& instruction : try_code.instructions) {
        if (instruction.kind != birch::dex::InstructionKind::Switch) continue;
        assert(std::find(instruction.targets.begin(), instruction.targets.end(),
                         handler_address) == instruction.targets.end());
    }
    return 0;
}
