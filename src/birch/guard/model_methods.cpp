#include "birch/guard/model_lowering.h"

#include "birch/dex/builder.h"
#include "birch/dex/code.h"
#include "birch/dex/cloner.h"
#include "birch/dex/remap.h"
#include "birch/dex/verifier.h"
#include "birch/guard/scope.h"
#include "birch/guard/constant_runtime.h"
#include "birch/guard/opaque_runtime.h"
#include "birch/guard/string_runtime.h"
#include "birch/utils/hash.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <map>
#include <span>
#include <iterator>
#include <type_traits>
#include <utility>

#include "model_methods.h"
#include "model_support.h"
#include "model_metadata.h"

namespace birch::guard::detail {
namespace {

dex::MethodBodySpec BuildStateFragmentBody(
    const dex::ClassSpec& klass, const dex::MethodSpec& original,
    const dex::MethodSpec& target, bool target_accepts_state,
    std::uint64_t state) {
    const auto is_static = (original.access_flags & kStatic) != 0U;
    const auto returns = BuildReturnSequence(original.return_type);
    dex::MethodBodySpec body;
    body.ins_size = static_cast<std::uint16_t>(original.body.ins_size + 1U);
    body.registers_size = static_cast<std::uint16_t>(
        returns.local_words + body.ins_size);
    auto arguments = InputRegisters(returns.local_words, body.ins_size);
    const auto state_register = arguments.back();
    const auto xor_literal = static_cast<std::uint8_t>(state | 1U);
    const auto add_literal = static_cast<std::uint8_t>((state >> 29U) | 1U);
    body.code_units.insert(body.code_units.end(), {
        static_cast<std::uint16_t>(0xdfU | (state_register << 8U)),
        static_cast<std::uint16_t>(state_register | (xor_literal << 8U)),
        static_cast<std::uint16_t>(0xd8U | (state_register << 8U)),
        static_cast<std::uint16_t>(state_register | (add_literal << 8U)),
    });
    if (!target_accepts_state) arguments.pop_back();
    body.outs_size = static_cast<std::uint16_t>(arguments.size());
    AppendInvoke(body.code_units, is_static ? 0x71U : 0x70U, arguments,
                 body, MethodReferenceFor(klass, target));
    body.code_units.insert(body.code_units.end(), returns.code.begin(),
                           returns.code.end());
    return body;
}


bool StateWrapperEligible(const dex::MethodSpec& method) {
    if (!HasTransformableBody(method) || method.body.ins_size > 4U) {
        return false;
    }
    const auto returns = BuildReturnSequence(method.return_type);
    return static_cast<std::uint32_t>(method.body.ins_size) + returns.local_words <=
           0x0fU;
}


std::optional<dex::MethodSpec> BuildTailLoopHelper(
    const dex::ClassSpec& klass, const dex::MethodSpec& original,
    std::string name) {
    // Passing every live register through the recursive call is only
    // type-safe without whole-program register typing when all registers are
    // incoming parameter words. Other loop shapes fail closed.
    if (original.body.registers_size != original.body.ins_size ||
        original.body.ins_size == 0U || original.body.ins_size >= 5U ||
        !original.body.try_regions.empty() ||
        original.body.registers_size >= 0xffU) {
        return std::nullopt;
    }
    const auto returns = BuildReturnSequence(original.return_type);
    if (returns.local_words > original.body.ins_size) return std::nullopt;

    enum class FixupWidth : std::uint8_t { Branch8, Branch16, Branch32 };
    struct Instruction {
        std::uint32_t offset{};
        std::uint32_t width{};
        std::uint8_t opcode{};
        std::optional<std::uint32_t> target;
        bool recursive_back_edge{};
    };
    struct Fixup {
        std::uint32_t output_offset{};
        std::uint32_t old_target{};
        FixupWidth width{FixupWidth::Branch16};
    };

    std::vector<Instruction> instructions;
    bool has_exit = false;
    bool has_conditional = false;
    std::size_t recursive_edges = 0U;
    for (std::size_t cursor = 0U;
         cursor < original.body.code_units.size();) {
        const auto width = BodyInstructionWidth(original.body, cursor);
        if (width == 0U) return std::nullopt;
        const auto first = original.body.code_units[cursor];
        const auto opcode = static_cast<std::uint8_t>(first & 0xffU);
        // Payload users and payload data need a general layout writer. They
        // are left to CFF rather than partially relocating a loop here.
        if (opcode == 0x26U || opcode == 0x2bU || opcode == 0x2cU ||
            (opcode == 0x00U && first != 0x0000U)) {
            return std::nullopt;
        }
        std::optional<std::int64_t> relative;
        if (opcode == 0x28U) {
            relative = static_cast<std::int8_t>(first >> 8U);
        } else if (opcode == 0x29U ||
                   (opcode >= 0x32U && opcode <= 0x3dU)) {
            relative = static_cast<std::int16_t>(
                original.body.code_units[cursor + 1U]);
        } else if (opcode == 0x2aU) {
            const auto bits = static_cast<std::uint32_t>(
                original.body.code_units[cursor + 1U]) |
                static_cast<std::uint32_t>(
                    original.body.code_units[cursor + 2U]) << 16U;
            relative = static_cast<std::int32_t>(bits);
        }
        Instruction instruction{
            static_cast<std::uint32_t>(cursor),
            static_cast<std::uint32_t>(width), opcode, std::nullopt, false};
        if (relative.has_value()) {
            const auto target = static_cast<std::int64_t>(cursor) + *relative;
            if (target < 0 || target >= static_cast<std::int64_t>(
                    original.body.code_units.size())) {
                return std::nullopt;
            }
            instruction.target = static_cast<std::uint32_t>(target);
            if (target <= static_cast<std::int64_t>(cursor)) {
                if (opcode < 0x28U || opcode > 0x2aU) {
                    return std::nullopt;
                }
                instruction.recursive_back_edge = true;
                ++recursive_edges;
            }
        }
        has_conditional = has_conditional ||
            (opcode >= 0x32U && opcode <= 0x3dU);
        has_exit = has_exit || (opcode >= 0x0eU && opcode <= 0x11U);
        instructions.push_back(instruction);
        cursor += width;
    }
    if (recursive_edges == 0U || !has_conditional || !has_exit) {
        return std::nullopt;
    }

    dex::MethodSpec helper;
    helper.name = std::move(name);
    helper.return_type = original.return_type;
    helper.parameter_types = original.parameter_types;
    helper.parameter_types.push_back("I");
    const auto is_static = (original.access_flags & kStatic) != 0U;
    helper.access_flags = kPrivate | kSynthetic | (is_static ? kStatic : 0U);
    helper.body.ins_size = static_cast<std::uint16_t>(
        original.body.ins_size + 1U);
    helper.body.registers_size = static_cast<std::uint16_t>(
        original.body.registers_size + 1U);
    helper.body.outs_size = std::max(
        original.body.outs_size, helper.body.ins_size);
    const auto depth_register = static_cast<std::uint16_t>(
        helper.body.registers_size - 1U);
    const auto arguments = InputRegisters(0U, helper.body.ins_size);

    std::map<std::uint32_t, std::uint32_t> old_to_new;
    std::map<std::uint32_t, std::uint32_t> old_unit_to_new;
    std::vector<Fixup> fixups;
    for (const auto& instruction : instructions) {
        const auto output_at = static_cast<std::uint32_t>(
            helper.body.code_units.size());
        old_to_new.emplace(instruction.offset, output_at);
        if (instruction.recursive_back_edge) {
            helper.body.code_units.push_back(static_cast<std::uint16_t>(
                0x3dU | (depth_register << 8U))); // if-lez depth, loop header
            helper.body.code_units.push_back(0U);
            fixups.push_back(
                {output_at, *instruction.target, FixupWidth::Branch16});
            helper.body.code_units.push_back(static_cast<std::uint16_t>(
                0xd8U | (depth_register << 8U)));
            helper.body.code_units.push_back(static_cast<std::uint16_t>(
                depth_register | 0xff00U)); // depth -= 1
            AppendInvoke(helper.body.code_units,
                         is_static ? 0x71U : 0x70U, arguments, helper.body,
                         MethodReferenceFor(klass, helper));
            helper.body.code_units.insert(helper.body.code_units.end(),
                                          returns.code.begin(),
                                          returns.code.end());
            continue;
        }
        helper.body.code_units.insert(
            helper.body.code_units.end(),
            original.body.code_units.begin() + instruction.offset,
            original.body.code_units.begin() + instruction.offset +
                instruction.width);
        for (std::uint32_t word = 0U; word < instruction.width; ++word) {
            old_unit_to_new.emplace(instruction.offset + word,
                                    output_at + word);
        }
        if (!instruction.target.has_value()) continue;
        const auto fixup_width = instruction.opcode == 0x28U ?
            FixupWidth::Branch8 : instruction.opcode == 0x2aU ?
                FixupWidth::Branch32 : FixupWidth::Branch16;
        fixups.push_back({output_at, *instruction.target, fixup_width});
    }

    for (const auto& fixup : fixups) {
        const auto target = old_to_new.find(fixup.old_target);
        if (target == old_to_new.end()) return std::nullopt;
        const auto displacement = static_cast<std::int64_t>(target->second) -
            static_cast<std::int64_t>(fixup.output_offset);
        if (displacement == 0) return std::nullopt;
        if (fixup.width == FixupWidth::Branch8) {
            if (displacement < std::numeric_limits<std::int8_t>::min() ||
                displacement > std::numeric_limits<std::int8_t>::max()) {
                return std::nullopt;
            }
            helper.body.code_units[fixup.output_offset] =
                static_cast<std::uint16_t>(
                    (helper.body.code_units[fixup.output_offset] & 0x00ffU) |
                    (static_cast<std::uint16_t>(
                         static_cast<std::uint8_t>(displacement)) << 8U));
        } else if (fixup.width == FixupWidth::Branch16) {
            if (displacement < std::numeric_limits<std::int16_t>::min() ||
                displacement > std::numeric_limits<std::int16_t>::max()) {
                return std::nullopt;
            }
            helper.body.code_units[fixup.output_offset + 1U] =
                static_cast<std::uint16_t>(
                    static_cast<std::int16_t>(displacement));
        } else {
            if (displacement < std::numeric_limits<std::int32_t>::min() ||
                displacement > std::numeric_limits<std::int32_t>::max()) {
                return std::nullopt;
            }
            const auto bits = static_cast<std::uint32_t>(
                static_cast<std::int32_t>(displacement));
            helper.body.code_units[fixup.output_offset + 1U] =
                static_cast<std::uint16_t>(bits);
            helper.body.code_units[fixup.output_offset + 2U] =
                static_cast<std::uint16_t>(bits >> 16U);
        }
    }

    const auto remap_reference = [&](const auto& reference,
                                     std::uint32_t code_unit,
                                     bool wide = false) {
        const auto found = old_unit_to_new.find(code_unit);
        if (found == old_unit_to_new.end()) return false;
        helper.body.references.push_back(
            {reference, found->second, wide});
        return true;
    };
    for (const auto& patch : original.body.references) {
        if (!remap_reference(patch.reference, patch.code_unit, patch.wide)) {
            return std::nullopt;
        }
    }
    for (const auto& patch : original.body.invoke_references) {
        if (!remap_reference(patch.reference, patch.code_unit)) {
            return std::nullopt;
        }
    }
    if (original.body.invoke_reference.has_value() &&
        !remap_reference(*original.body.invoke_reference,
                         original.body.invoke_reference_unit)) {
        return std::nullopt;
    }
    for (const auto& patch : original.body.string_references) {
        if (!remap_reference(patch.value, patch.code_unit)) {
            return std::nullopt;
        }
    }
    // Address-bearing debug events cannot be retained after block growth.
    // The global release configuration also strips all DEX debug sections.
    helper.body.debug_info.reset();
    return helper;
}


struct InlineCandidate {
    struct UnaryIntOperation {
        std::uint8_t opcode{};
        std::uint16_t literal{};
    };

    dex::MethodReference reference;
    bool returns_void{};
    bool returns_object{};
    bool returns_wide{};
    std::vector<std::uint16_t> constant_instruction;
    std::optional<std::uint16_t> parameter_word;
    std::optional<UnaryIntOperation> unary_int;
};


} // namespace

void ModelMethodStructure::ApplyTailRecursionBeforeClassSplit(
    dex::ClassSpec& klass, const GuardConfig& config,
    ModelLoweringResult& report) {
    const auto& pass = config.passes.at("cfg.tail_recursion");
    if (!pass.enabled) return;

    std::set<std::string, std::less<>> used_names;
    for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (const auto& method : *methods) used_names.insert(method.name);
    }
    std::size_t ordinal = 0U;
    const auto transform_group = [&](std::vector<dex::MethodSpec>& methods) {
        const auto original_count = methods.size();
        for (std::size_t index = 0U; index < original_count; ++index, ++ordinal) {
            auto& method = methods[index];
            const auto key = klass.descriptor + "->" + method.name;
            if (!Selected(pass, config.seed, key, 0x5441494cU) ||
                !StateWrapperEligible(method) ||
                config.budget.max_call_depth_increase == 0U) {
                continue;
            }
            auto helper_name = SyntheticName(
                config.seed, "tail-loop", ordinal, used_names);
            auto helper = BuildTailLoopHelper(klass, method, helper_name);
            if (!helper.has_value()) continue;
            used_names.insert(std::move(helper_name));
            const auto depth = static_cast<std::uint8_t>(std::min<std::uint32_t>(
                7U, std::min<std::uint32_t>(
                    config.budget.max_call_depth_increase,
                    1U + static_cast<std::uint32_t>(pass.intensity * 6.0))));
            method.body = BuildWrapperBody(klass, method, *helper, depth);
            methods.push_back(std::move(*helper));
            ++report.tail_recursive_methods;
            ++report.pass_applications["cfg.tail_recursion"];
        }
    };
    transform_group(klass.direct_methods);
    transform_group(klass.virtual_methods);
}


void ModelMethodStructure::InlineTrivialMethods(dex::ClassSpec& klass, const GuardConfig& config,
                          ModelLoweringResult& report) {
    const auto& pass = config.passes.at("structure.method_inlining");
    if (!pass.enabled) return;
    std::vector<InlineCandidate> candidates;
    for (const auto& method : klass.direct_methods) {
        if ((method.access_flags & (kPrivate | kStatic)) != (kPrivate | kStatic) ||
            (method.access_flags & (kNative | kAbstract)) != 0U ||
            method.body.code_units.empty() ||
            !method.body.references.empty() ||
            !method.body.invoke_references.empty() ||
            method.body.invoke_reference.has_value() ||
            !method.body.string_references.empty() ||
            !method.body.try_regions.empty()) {
            continue;
        }
        if (method.parameter_types.empty() && method.return_type == "V" &&
            method.body.code_units == std::vector<std::uint16_t>{0x000eU}) {
            candidates.push_back(
                {MethodReferenceFor(klass, method), true, false, false, {},
                 std::nullopt, std::nullopt});
            continue;
        }
        const auto object = !method.return_type.empty() &&
            (method.return_type.front() == 'L' || method.return_type.front() == '[');
        const auto wide = method.return_type == "J" ||
                          method.return_type == "D";
        const auto integral = method.return_type == "Z" || method.return_type == "B" ||
            method.return_type == "S" || method.return_type == "C" ||
            method.return_type == "I";
        if (!method.parameter_types.empty() &&
            method.body.code_units.size() == 1U &&
            (object || integral || wide)) {
            const auto return_opcode = static_cast<std::uint8_t>(
                method.body.code_units.front() & 0xffU);
            const auto return_register = static_cast<std::uint16_t>(
                method.body.code_units.front() >> 8U);
            const auto parameter_base = static_cast<std::uint16_t>(
                method.body.registers_size - method.body.ins_size);
            if (((object && return_opcode == 0x11U) ||
                 (integral && return_opcode == 0x0fU) ||
                 (wide && return_opcode == 0x10U)) &&
                return_register >= parameter_base &&
                return_register - parameter_base < method.body.ins_size) {
                const auto word = static_cast<std::uint16_t>(
                    return_register - parameter_base);
                std::uint16_t cursor = 0U;
                bool valid_word = false;
                for (const auto& parameter : method.parameter_types) {
                    if (cursor == word) {
                        const auto parameter_object = !parameter.empty() &&
                            (parameter.front() == 'L' || parameter.front() == '[');
                        const auto parameter_integral = parameter == "Z" ||
                            parameter == "B" || parameter == "S" ||
                            parameter == "C" || parameter == "I";
                        valid_word = (object && parameter_object) ||
                                     (integral && parameter_integral) ||
                                     (wide && parameter == method.return_type);
                        break;
                    }
                    cursor = static_cast<std::uint16_t>(
                        cursor + (parameter == "J" || parameter == "D" ? 2U : 1U));
                }
                if (valid_word) {
                    candidates.push_back({MethodReferenceFor(klass, method),
                                          false, object, wide, {}, word,
                                          std::nullopt});
                    continue;
                }
            }
        }
        if (method.parameter_types.size() == 1U && integral &&
            method.body.code_units.size() == 3U) {
            const auto operation = method.body.code_units[0U];
            const auto operation_opcode = static_cast<std::uint8_t>(
                operation & 0xffU);
            const auto return_word = method.body.code_units[2U];
            const auto return_opcode = static_cast<std::uint8_t>(
                return_word & 0xffU);
            const auto return_register = static_cast<std::uint16_t>(
                return_word >> 8U);
            const auto parameter_base = static_cast<std::uint16_t>(
                method.body.registers_size - method.body.ins_size);
            std::uint16_t destination = 0U;
            std::uint16_t source = 0U;
            bool encodable = false;
            if (operation_opcode >= 0xd0U && operation_opcode <= 0xd7U) {
                destination = static_cast<std::uint16_t>(
                    (operation >> 8U) & 0x0fU);
                source = static_cast<std::uint16_t>(operation >> 12U);
                encodable = true;
            } else if (operation_opcode >= 0xd8U &&
                       operation_opcode <= 0xe2U) {
                destination = static_cast<std::uint16_t>(operation >> 8U);
                source = static_cast<std::uint16_t>(
                    method.body.code_units[1U] & 0x00ffU);
                encodable = true;
            }
            if (encodable && return_opcode == 0x0fU &&
                return_register == destination && source == parameter_base) {
                candidates.push_back({
                    MethodReferenceFor(klass, method), false, false, false, {},
                    0U,
                    InlineCandidate::UnaryIntOperation{
                        operation_opcode, method.body.code_units[1U]}});
                continue;
            }
        }
        if (!method.parameter_types.empty()) continue;
        const auto first_opcode = static_cast<std::uint8_t>(
            method.body.code_units.front() & 0xffU);
        std::size_t constant_width = 0U;
        if ((integral || object) && first_opcode == 0x12U) {
            constant_width = 1U;
        } else if (integral &&
                   (first_opcode == 0x13U || first_opcode == 0x15U)) {
            constant_width = 2U;
        } else if (integral && first_opcode == 0x14U) {
            constant_width = 3U;
        } else if (wide &&
                   (first_opcode == 0x16U || first_opcode == 0x19U)) {
            constant_width = 2U;
        } else if (wide && first_opcode == 0x17U) {
            constant_width = 3U;
        }
        if (constant_width == 0U ||
            method.body.code_units.size() != constant_width + 1U) {
            continue;
        }
        const auto source_register = static_cast<std::uint16_t>(
            first_opcode == 0x12U ?
                ((method.body.code_units[0U] >> 8U) & 0x0fU) :
                (method.body.code_units[0U] >> 8U));
        const auto return_opcode = static_cast<std::uint8_t>(
            method.body.code_units[constant_width] & 0xffU);
        const auto return_register = static_cast<std::uint16_t>(
            method.body.code_units[constant_width] >> 8U);
        const auto literal = static_cast<std::uint16_t>(
            method.body.code_units[0U] & 0xf000U);
        if (source_register != return_register ||
            (object && (return_opcode != 0x11U ||
                        first_opcode != 0x12U || literal != 0U)) ||
            (integral && return_opcode != 0x0fU) ||
            (wide && return_opcode != 0x10U) ||
            (!object && !integral && !wide)) {
            continue;
        }
        candidates.push_back(
            {MethodReferenceFor(klass, method), false, object, wide,
             std::vector<std::uint16_t>(
                  method.body.code_units.begin(),
                  method.body.code_units.begin() + constant_width),
              std::nullopt, std::nullopt});
    }
    const auto matches = [](const dex::MethodReference& left,
                            const dex::MethodReference& right) {
        return left.owner == right.owner && left.name == right.name &&
               left.return_type == right.return_type &&
               left.parameter_types == right.parameter_types;
    };
    for (auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (auto& caller : *methods) {
            auto& references = caller.body.references;
            for (auto iterator = references.begin(); iterator != references.end();) {
                const auto* target = std::get_if<dex::MethodReference>(
                    &iterator->reference);
                const auto candidate = target == nullptr ? candidates.end() :
                    std::find_if(candidates.begin(), candidates.end(),
                        [&](const auto& value) { return matches(value.reference, *target); });
                if (candidate == candidates.end() || iterator->wide ||
                    iterator->code_unit == 0U) {
                    ++iterator;
                    continue;
                }
                const auto invoke = iterator->code_unit - 1U;
                if (invoke + 2U >= caller.body.code_units.size() ||
                    ((caller.body.code_units[invoke] & 0xffU) != 0x71U &&
                     (caller.body.code_units[invoke] & 0xffU) != 0x77U) ||
                    !Selected(pass, config.seed,
                        klass.descriptor + "->" + caller.name + "->" + target->name,
                        0x494e4c4eU)) {
                    ++iterator;
                    continue;
                }
                const auto invoke_opcode = static_cast<std::uint8_t>(
                    caller.body.code_units[invoke] & 0xffU);
                const auto argument_count = invoke_opcode == 0x71U ?
                    static_cast<std::uint16_t>(
                        caller.body.code_units[invoke] >> 12U) :
                    static_cast<std::uint16_t>(
                        caller.body.code_units[invoke] >> 8U);
                if (!candidate->parameter_word.has_value() &&
                    argument_count != 0U) {
                    ++iterator;
                    continue;
                }
                if (candidate->returns_void) {
                    caller.body.code_units[invoke] = 0x002aU; // goto/32 +3
                    caller.body.code_units[invoke + 1U] = 3U;
                    caller.body.code_units[invoke + 2U] = 0U;
                } else {
                    const auto move_at = invoke + 3U;
                    if (move_at >= caller.body.code_units.size()) {
                        ++iterator;
                        continue;
                    }
                    const auto move = caller.body.code_units[move_at];
                    const auto expected = candidate->returns_object ? 0x0cU :
                        (candidate->returns_wide ? 0x0bU : 0x0aU);
                    const auto destination = static_cast<std::uint16_t>(move >> 8U);
                    if ((move & 0xffU) != expected) {
                        ++iterator;
                        continue;
                    }
                    if (candidate->parameter_word.has_value()) {
                        if (*candidate->parameter_word >= argument_count) {
                            ++iterator;
                            continue;
                        }
                        std::uint16_t source = 0U;
                        if (invoke_opcode == 0x77U) {
                            source = static_cast<std::uint16_t>(
                                caller.body.code_units[invoke + 2U] +
                                *candidate->parameter_word);
                        } else {
                            const auto packed = caller.body.code_units[invoke + 2U];
                            const std::array<std::uint16_t, 5U> registers{
                                static_cast<std::uint16_t>(packed & 0x0fU),
                                static_cast<std::uint16_t>((packed >> 4U) & 0x0fU),
                                static_cast<std::uint16_t>((packed >> 8U) & 0x0fU),
                                static_cast<std::uint16_t>((packed >> 12U) & 0x0fU),
                                static_cast<std::uint16_t>(
                                    (caller.body.code_units[invoke] >> 8U) & 0x0fU),
                            };
                            source = registers[*candidate->parameter_word];
                        }
                        if (candidate->unary_int.has_value()) {
                            const auto operation = *candidate->unary_int;
                            if (operation.opcode >= 0xd0U &&
                                operation.opcode <= 0xd7U) {
                                if (destination > 0x0fU || source > 0x0fU) {
                                    ++iterator;
                                    continue;
                                }
                                caller.body.code_units[invoke] =
                                    static_cast<std::uint16_t>(
                                        operation.opcode |
                                        (destination << 8U) | (source << 12U));
                                caller.body.code_units[invoke + 1U] =
                                    operation.literal;
                            } else {
                                if (destination > 0xffU || source > 0xffU) {
                                    ++iterator;
                                    continue;
                                }
                                caller.body.code_units[invoke] =
                                    static_cast<std::uint16_t>(
                                        operation.opcode | (destination << 8U));
                                caller.body.code_units[invoke + 1U] =
                                    static_cast<std::uint16_t>(
                                        (operation.literal & 0xff00U) | source);
                            }
                            caller.body.code_units[invoke + 2U] = 0x0029U;
                            caller.body.code_units[move_at] = 2U;
                        } else if (destination <= 0x0fU && source <= 0x0fU) {
                            const auto move_opcode = candidate->returns_object ?
                                0x07U : (candidate->returns_wide ? 0x04U : 0x01U);
                            caller.body.code_units[invoke] =
                                static_cast<std::uint16_t>(
                                    move_opcode | (destination << 8U) |
                                    (source << 12U));
                            caller.body.code_units[invoke + 1U] = 0x002aU;
                            caller.body.code_units[invoke + 2U] = 3U;
                            caller.body.code_units[move_at] = 0U;
                        } else {
                            const auto move_opcode = candidate->returns_object ?
                                0x08U : (candidate->returns_wide ? 0x05U : 0x02U);
                            caller.body.code_units[invoke] =
                                static_cast<std::uint16_t>(
                                    move_opcode | (destination << 8U));
                            caller.body.code_units[invoke + 1U] = source;
                            caller.body.code_units[invoke + 2U] = 0x0029U;
                            caller.body.code_units[move_at] = 2U;
                        }
                    } else {
                        auto constant = candidate->constant_instruction;
                        if (constant.empty()) {
                            ++iterator;
                            continue;
                        }
                        const auto opcode = static_cast<std::uint8_t>(
                            constant.front() & 0xffU);
                        if (opcode == 0x12U) {
                            if (destination > 0x0fU) {
                                ++iterator;
                                continue;
                            }
                            constant.front() = static_cast<std::uint16_t>(
                                (constant.front() & 0xf000U) |
                                (destination << 8U) | opcode);
                        } else {
                            constant.front() = static_cast<std::uint16_t>(
                                (constant.front() & 0x00ffU) |
                                (destination << 8U));
                        }
                        std::copy(constant.begin(), constant.end(),
                                  caller.body.code_units.begin() + invoke);
                        if (constant.size() == 1U) {
                            caller.body.code_units[invoke + 1U] = 0x002aU;
                            caller.body.code_units[invoke + 2U] = 3U;
                            caller.body.code_units[invoke + 3U] = 0U;
                        } else if (constant.size() == 2U) {
                            caller.body.code_units[invoke + 2U] = 0x0029U;
                            caller.body.code_units[invoke + 3U] = 2U;
                        } else {
                            caller.body.code_units[invoke + 3U] = 0x0128U;
                        }
                    }
                }
                iterator = references.erase(iterator);
                ++report.inlined_calls;
                ++report.pass_applications["structure.method_inlining"];
            }
        }
    }
}


void ModelMethodStructure::TransformClass(
    dex::ClassSpec& klass, const GuardConfig& config,
    ModelLoweringResult& report,
    std::vector<dex::ClassSpec>& generated_classes,
    std::set<std::string, std::less<>>& used_descriptors) {
    const auto& tail_pass = config.passes.at("cfg.tail_recursion");
    const auto& outline_pass = config.passes.at("structure.method_outlining");
    const auto& split_pass = config.passes.at("structure.method_splitting");
    const auto& proxy_pass = config.passes.at("structure.proxy_stubs");
    ModelMetadata::RenameDebugParameters(klass, config, report);
    ModelMetadata::AddMetadataNoise(klass, config, report);
    std::set<std::string, std::less<>> used_names;
    for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (const auto& method : *methods) used_names.insert(method.name);
    }
    std::vector<dex::MethodSpec> generated;
    std::optional<dex::ClassSpec> proxy_class;
    std::size_t ordinal = 0U;
    const auto transform_group = [&](std::vector<dex::MethodSpec>& methods) {
        const auto original_count = methods.size();
        for (std::size_t i = 0U; i < original_count; ++i, ++ordinal) {
            auto& method = methods[i];
            const auto self_recursive = [&]() {
                const auto is_self = [&](const dex::MethodReference& reference) {
                    return reference.owner == klass.descriptor &&
                           reference.name == method.name;
                };
                if (method.body.invoke_reference.has_value() &&
                    is_self(*method.body.invoke_reference)) {
                    return true;
                }
                for (const auto& patch : method.body.invoke_references) {
                    if (is_self(patch.reference)) return true;
                }
                for (const auto& patch : method.body.references) {
                    if (const auto* reference =
                            std::get_if<dex::MethodReference>(&patch.reference);
                        reference != nullptr && is_self(*reference)) {
                        return true;
                    }
                }
                return false;
            }();
            if (self_recursive &&
                config.passes.at("structure.class_splitting").enabled) {
                continue;
            }
            const auto key = klass.descriptor + "->" + method.name;
            // When class splitting is enabled, tail lowering already ran on
            // the original body before splitting. Do not re-run it on the
            // generated helper/wrapper graph.
            const auto tail = !config.passes.at("structure.class_splitting").enabled &&
                Selected(tail_pass, config.seed, key, 0x5441494cU);
            const auto split = Selected(split_pass, config.seed, key, 0x53504c54U);
            const auto proxy = Selected(proxy_pass, config.seed, key, 0x50524f58U);
            const auto outline = Selected(outline_pass, config.seed, key, 0x4f55544cU);
            if (!tail && !split && !proxy && !outline) continue;
            if (!HasTransformableBody(method)) {
                ++report.skipped_methods;
                continue;
            }
            enum class Strategy {
                Tail,
                Split,
                Proxy,
                Outline,
            };
            std::array<Strategy, 4U> order{
                Strategy::Tail, Strategy::Split, Strategy::Proxy, Strategy::Outline};
            if (config.strength.per_method_strategy &&
                config.passes.at("strength.per_method_randomization").enabled) {
                auto state = utils::StableHash64(key, config.seed ^ 0x6b65797374726174ULL);
                // Loop-to-recursion must inspect the original CFG. Randomize
                // the composable wrapper layers while keeping that semantic
                // transform first.
                for (std::size_t index = order.size(); index > 2U; --index) {
                    state ^= state << 13U;
                    state ^= state >> 7U;
                    state ^= state << 17U;
                    std::swap(order[index - 1U],
                              order[1U + state % (index - 1U)]);
                }
            }
            bool transformed = false;
            for (const auto strategy : order) {
                if (strategy == Strategy::Tail && tail &&
                    StateWrapperEligible(method) &&
                    config.budget.max_call_depth_increase != 0U) {
                    auto tail_name = SyntheticName(
                        config.seed, "tail-loop", ordinal, used_names);
                    auto tail_method = BuildTailLoopHelper(
                        klass, method, tail_name);
                    if (!tail_method.has_value()) continue;
                    used_names.insert(std::move(tail_name));
                    const auto depth = static_cast<std::uint8_t>(
                        std::min<std::uint32_t>(
                            7U, std::min<std::uint32_t>(
                                config.budget.max_call_depth_increase,
                                1U + static_cast<std::uint32_t>(
                                    tail_pass.intensity * 6.0))));
                    method.body = BuildWrapperBody(
                        klass, method, *tail_method, depth);
                    generated.push_back(std::move(*tail_method));
                    ++report.tail_recursive_methods;
                    ++report.pass_applications["cfg.tail_recursion"];
                    transformed = true;
                } else if (strategy == Strategy::Split && split &&
                           StateWrapperEligible(method)) {
                    const auto requested_fragments =
                        2U + static_cast<std::uint32_t>(
                            std::ceil(split_pass.intensity * 6.0));
                    const auto fragment_count = std::min<std::uint32_t>(
                        requested_fragments,
                        config.budget.max_call_depth_increase);
                    if (fragment_count >= 2U) {
                        const auto helper_access = kPrivate | kSynthetic |
                            ((method.access_flags & kStatic) != 0U ? kStatic : 0U);
                        auto original_body = std::move(method.body);
                        method.body = {};
                        method.body.ins_size = original_body.ins_size;

                        std::vector<dex::MethodSpec> fragments;
                        fragments.reserve(fragment_count);
                        dex::MethodSpec body_fragment;
                        body_fragment.name = SyntheticName(
                            config.seed, "split-body", ordinal, used_names);
                        used_names.insert(body_fragment.name);
                        body_fragment.return_type = method.return_type;
                        body_fragment.parameter_types = method.parameter_types;
                        body_fragment.access_flags = helper_access;
                        body_fragment.body = std::move(original_body);
                        fragments.push_back(std::move(body_fragment));

                        for (std::uint32_t fragment = 1U;
                             fragment < fragment_count; ++fragment) {
                            dex::MethodSpec hop;
                            hop.name = SyntheticName(
                                config.seed,
                                "split-hop-" + std::to_string(fragment),
                                ordinal, used_names);
                            used_names.insert(hop.name);
                            hop.return_type = method.return_type;
                            hop.parameter_types = method.parameter_types;
                            hop.parameter_types.push_back("I");
                            hop.access_flags = helper_access;
                            hop.body = BuildStateFragmentBody(
                                klass, method, fragments.back(), fragment > 1U,
                                utils::StableHash64(
                                    key + ":fragment:" +
                                        std::to_string(fragment),
                                    config.seed));
                            fragments.push_back(std::move(hop));
                        }
                        const auto initial_state = static_cast<std::uint8_t>(
                            1U + (utils::StableHash64(
                                key, config.seed ^ 0x53504c4954535441ULL) %
                                  15U));
                        method.body = BuildWrapperBody(
                            klass, method, fragments.back(), initial_state);
                        generated.insert(
                            generated.end(),
                            std::make_move_iterator(fragments.begin()),
                            std::make_move_iterator(fragments.end()));
                        ++report.split_methods;
                        ++report.pass_applications[
                            "structure.method_splitting"];
                        transformed = true;
                    }
                } else if (strategy == Strategy::Proxy && proxy &&
                           !HasInvokeSuper(method)) {
                    if (!proxy_class.has_value()) {
                        dex::ClassSpec generated_proxy;
                        generated_proxy.descriptor = SyntheticClassDescriptor(
                            "proxy", klass.descriptor, config.seed, ordinal,
                            used_descriptors);
                        used_descriptors.insert(generated_proxy.descriptor);
                        generated_proxy.access_flags = 0x1011U;
                        proxy_class = std::move(generated_proxy);
                    }
                    dex::MethodSpec body_method;
                    body_method.name = SyntheticName(
                        config.seed, "proxy-body", ordinal, used_names);
                    used_names.insert(body_method.name);
                    body_method.return_type = method.return_type;
                    body_method.parameter_types = method.parameter_types;
                    if ((method.access_flags & kStatic) == 0U) {
                        body_method.parameter_types.insert(
                            body_method.parameter_types.begin(), klass.descriptor);
                    }
                    body_method.access_flags = 0x1009U;
                    body_method.body = std::move(method.body);

                    dex::MethodSpec proxy_method;
                    proxy_method.name = SyntheticName(
                        config.seed, "proxy-hop", ordinal, used_names);
                    used_names.insert(proxy_method.name);
                    proxy_method.return_type = method.return_type;
                    proxy_method.parameter_types = body_method.parameter_types;
                    proxy_method.access_flags = 0x1009U;
                    proxy_method.body = BuildStaticForwardBody(
                        method.return_type, body_method.body.ins_size,
                        MethodReferenceFor(klass, body_method));
                    method.body = BuildStaticForwardBody(
                        method.return_type, body_method.body.ins_size,
                        {proxy_class->descriptor, proxy_method.name,
                         proxy_method.return_type,
                         proxy_method.parameter_types});
                    generated.push_back(std::move(body_method));
                    proxy_class->direct_methods.push_back(
                        std::move(proxy_method));
                    ++report.proxy_methods;
                    ++report.pass_applications["structure.proxy_stubs"];
                    transformed = true;
                } else if (strategy == Strategy::Outline && outline) {
                    const auto helper_access = kPrivate | kSynthetic |
                        ((method.access_flags & kStatic) != 0U ? kStatic : 0U);
                    dex::MethodSpec body_method;
                    body_method.name = SyntheticName(
                        config.seed, "outline", ordinal, used_names);
                    used_names.insert(body_method.name);
                    body_method.return_type = method.return_type;
                    body_method.parameter_types = method.parameter_types;
                    body_method.access_flags = helper_access;
                    body_method.body = std::move(method.body);
                    method.body = BuildWrapperBody(klass, method, body_method,
                                                   std::nullopt);
                    generated.push_back(std::move(body_method));
                    ++report.outlined_methods;
                    ++report.pass_applications["structure.method_outlining"];
                    transformed = true;
                }
            }
            if (!transformed) ++report.skipped_methods;
        }
    };
    transform_group(klass.direct_methods);
    transform_group(klass.virtual_methods);
    if (!generated.empty()) {
        klass.direct_methods.insert(klass.direct_methods.end(),
                                    std::make_move_iterator(generated.begin()),
                                    std::make_move_iterator(generated.end()));
        ++report.transformed_classes;
    }
    if (proxy_class.has_value() && !proxy_class->direct_methods.empty()) {
        generated_classes.push_back(std::move(*proxy_class));
    }
}


} // namespace birch::guard::detail
