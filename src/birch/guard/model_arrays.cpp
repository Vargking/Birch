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

#include "model_arrays.h"
#include "model_support.h"

namespace birch::guard::detail {
namespace {

std::uint8_t ArrayGetOpcode(std::string_view element_type);


dex::MethodSpec BuildArrayElementAccessor(const dex::ClassSpec& klass,
                                          const ArrayAccessorPlan& plan) {
    const auto wide = TypeWordCount(plan.element_type) == 2U;
    const auto object = !plan.element_type.empty() &&
        (plan.element_type.front() == 'L' || plan.element_type.front() == '[');
    const auto array_register = static_cast<std::uint16_t>(wide ? 2U : 0U);
    const auto index_register = static_cast<std::uint16_t>(wide ? 3U : 2U);
    const auto result_register = static_cast<std::uint16_t>(wide ? 0U : 1U);
    dex::MethodSpec accessor;
    accessor.name = plan.accessor_name;
    accessor.return_type = plan.element_type;
    accessor.parameter_types = {"I"};
    accessor.access_flags = 0x1009U; // public static synthetic
    accessor.body.registers_size = static_cast<std::uint16_t>(wide ? 4U : 3U);
    accessor.body.ins_size = 1U;
    accessor.body.outs_size = 0U;
    accessor.body.code_units = {
        static_cast<std::uint16_t>(0x62U | (array_register << 8U)), 0U,
        static_cast<std::uint16_t>(ArrayGetOpcode(plan.element_type) |
                                   (result_register << 8U)),
        static_cast<std::uint16_t>(array_register | (index_register << 8U)),
        static_cast<std::uint16_t>((wide ? 0x10U : object ? 0x11U : 0x0fU) |
                                   (result_register << 8U)),
    };
    accessor.body.references.push_back({
        dex::FieldReference{klass.descriptor, plan.field_name, plan.field_type},
        1U, false});
    return accessor;
}


std::uint8_t ArrayGetOpcode(std::string_view element_type) {
    if (element_type == "J" || element_type == "D") return 0x45U;
    if (!element_type.empty() &&
        (element_type.front() == 'L' || element_type.front() == '[')) {
        return 0x46U;
    }
    if (element_type == "Z") return 0x47U;
    if (element_type == "B") return 0x48U;
    if (element_type == "C") return 0x49U;
    if (element_type == "S") return 0x4aU;
    return 0x44U;
}


dex::MethodSpec BuildArraySplitInitializer(
    const dex::ClassSpec& klass, const ArrayAccessorPlan& plan) {
    dex::MethodSpec method;
    method.name = plan.split_init_name;
    method.return_type = "V";
    method.access_flags = kPrivate | kStatic | kSynthetic;
    method.body.registers_size = 7U;
    method.body.outs_size = 5U;
    auto& code = method.body.code_units;
    auto& references = method.body.references;
    code.push_back(0x0062U); // sget-object v0, source
    code.push_back(0U);
    references.push_back({dex::FieldReference{
        klass.descriptor, plan.field_name, plan.field_type}, 1U, false});
    const auto null_branch = code.size();
    code.insert(code.end(), {0x0038U, 0U}); // if-eqz v0, return
    // 12x encodes the destination in bits 8..11 and the source in
    // bits 12..15.  0x1021 would read v1 and write v0, which leaves the
    // source undefined on this freshly generated method.
    code.push_back(0x0121U); // array-length v1, v0
    code.insert(code.end(), {0x02d8U, 0x0101U}); // v2 = v1 + 1 (22b)
    code.insert(code.end(), {0x02e2U, 0x0102U}); // v2 >>>= 1 (22b)
    code.insert(code.end(), {0x2323U, 0U}); // new-array v3, v2
    references.push_back(
        {dex::TypeReference{plan.field_type},
         static_cast<std::uint32_t>(code.size() - 1U), false});
    code.insert(code.end(), {0x0491U, 0x0201U}); // v4 = v1 - v2 (23x)
    code.insert(code.end(), {0x4523U, 0U}); // new-array v5, v4
    references.push_back(
        {dex::TypeReference{plan.field_type},
         static_cast<std::uint32_t>(code.size() - 1U), false});
    code.push_back(0x0612U); // const/4 v6, 0
    AppendInvoke35c(code, 0x71U, {0U, 6U, 3U, 6U, 2U}, method.body,
                    {"Ljava/lang/System;", "arraycopy", "V",
                     {"Ljava/lang/Object;", "I", "Ljava/lang/Object;", "I", "I"}});
    AppendInvoke35c(code, 0x71U, {0U, 2U, 5U, 6U, 4U}, method.body,
                    {"Ljava/lang/System;", "arraycopy", "V",
                     {"Ljava/lang/Object;", "I", "Ljava/lang/Object;", "I", "I"}});
    code.insert(code.end(), {0x0369U, 0U}); // sput-object v3, first
    references.push_back({dex::FieldReference{
        klass.descriptor, plan.split_field_names[0U], plan.field_type},
        static_cast<std::uint32_t>(code.size() - 1U), false});
    code.insert(code.end(), {0x0569U, 0U}); // sput-object v5, second
    references.push_back({dex::FieldReference{
        klass.descriptor, plan.split_field_names[1U], plan.field_type},
        static_cast<std::uint32_t>(code.size() - 1U), false});
    const auto return_offset = code.size();
    code.push_back(0x000eU);
    code[null_branch + 1U] = static_cast<std::uint16_t>(
        return_offset - null_branch);
    return method;
}


dex::MethodSpec BuildArraySplitElementAccessor(
    const dex::ClassSpec& klass, const ArrayAccessorPlan& plan) {
    const auto wide = TypeWordCount(plan.element_type) == 2U;
    const auto object = !plan.element_type.empty() &&
        (plan.element_type.front() == 'L' || plan.element_type.front() == '[');
    const auto array_register = static_cast<std::uint16_t>(wide ? 2U : 0U);
    const auto length_register = static_cast<std::uint16_t>(wide ? 3U : 1U);
    const auto index_register = static_cast<std::uint16_t>(wide ? 4U : 2U);
    const auto result_register = static_cast<std::uint16_t>(wide ? 0U : 1U);
    const auto aget = ArrayGetOpcode(plan.element_type);
    const auto return_opcode = static_cast<std::uint8_t>(
        wide ? 0x10U : (object ? 0x11U : 0x0fU));

    dex::MethodSpec method;
    method.name = plan.accessor_name;
    method.return_type = plan.element_type;
    method.parameter_types = {"I"};
    method.access_flags = kPrivate | kStatic | kSynthetic;
    method.body.registers_size = static_cast<std::uint16_t>(wide ? 5U : 3U);
    method.body.ins_size = 1U;
    auto& code = method.body.code_units;
    auto& references = method.body.references;
    code.push_back(static_cast<std::uint16_t>(
        0x62U | (array_register << 8U)));
    code.push_back(0U);
    references.push_back({dex::FieldReference{
        klass.descriptor, plan.split_field_names[0U], plan.field_type},
        1U, false});
    const auto initialized_branch = code.size();
    code.insert(code.end(), {
        static_cast<std::uint16_t>(0x39U | (array_register << 8U)), 0U});
    AppendInvoke35c(code, 0x71U, {}, method.body,
                    {klass.descriptor, plan.split_init_name, "V", {}});
    code.push_back(static_cast<std::uint16_t>(
        0x62U | (array_register << 8U)));
    code.push_back(0U);
    references.push_back({dex::FieldReference{
        klass.descriptor, plan.split_field_names[0U], plan.field_type},
        static_cast<std::uint32_t>(code.size() - 1U), false});
    const auto initialized_offset = code.size();
    code[initialized_branch + 1U] = static_cast<std::uint16_t>(
        initialized_offset - initialized_branch);
    code.push_back(static_cast<std::uint16_t>(
        0x21U | (length_register << 8U) | (array_register << 12U)));
    const auto second_branch = code.size();
    code.push_back(static_cast<std::uint16_t>(
        0x35U | (index_register << 8U) | (length_register << 12U)));
    code.push_back(0U);
    code.push_back(static_cast<std::uint16_t>(aget | (result_register << 8U)));
    code.push_back(static_cast<std::uint16_t>(
        array_register | (index_register << 8U)));
    code.push_back(static_cast<std::uint16_t>(
        return_opcode | (result_register << 8U)));
    const auto second_offset = code.size();
    code.push_back(static_cast<std::uint16_t>(
        0xb1U | (index_register << 8U) | (length_register << 12U)));
    code.push_back(static_cast<std::uint16_t>(
        0x62U | (array_register << 8U)));
    code.push_back(0U);
    references.push_back({dex::FieldReference{
        klass.descriptor, plan.split_field_names[1U], plan.field_type},
        static_cast<std::uint32_t>(code.size() - 1U), false});
    code.push_back(static_cast<std::uint16_t>(aget | (result_register << 8U)));
    code.push_back(static_cast<std::uint16_t>(
        array_register | (index_register << 8U)));
    code.push_back(static_cast<std::uint16_t>(
        return_opcode | (result_register << 8U)));
    code[second_branch + 1U] = static_cast<std::uint16_t>(
        second_offset - second_branch);
    return method;
}


} // namespace

void ModelArrayProtection::AddArrayAccessors(dex::ClassSpec& klass, const GuardConfig& config,
                       std::vector<ArrayAccessorPlan>& plans) {
    const auto& virtualization = config.passes.at("data.array_virtualization");
    const auto& splitting = config.passes.at("data.array_splitting");
    if (!virtualization.enabled && !splitting.enabled) return;
    std::set<std::string, std::less<>> used_names;
    for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (const auto& method : *methods) used_names.insert(method.name);
    }
    std::size_t ordinal = 0U;
    const auto original_field_count = klass.static_fields.size();
    for (std::size_t field_index = 0U; field_index < original_field_count;
         ++field_index) {
        const auto field = klass.static_fields[field_index];
        if (field.type.empty() || field.type.front() != '[') {
            continue;
        }
        const auto key = klass.descriptor + "->" + field.name;
        const bool virtualize = Selected(virtualization, config.seed, key,
                                         0x41565254U);
        const bool split = (field.access_flags & (kPrivate | kStatic)) ==
                (kPrivate | kStatic) &&
            Selected(splitting, config.seed, key, 0x41525350U);
        if (!virtualize && !split) continue;
        ArrayAccessorPlan plan;
        plan.owner = klass.descriptor;
        plan.field_name = field.name;
        plan.field_type = field.type;
        plan.element_type = field.type.substr(1U);
        plan.virtualize = virtualize;
        plan.split = split;
        plan.accessor_name = SyntheticName(config.seed, split ? "array-split" :
                                           "array-virtual", ordinal++, used_names);
        used_names.insert(plan.accessor_name);
        if (split) {
            const auto first = SyntheticName(
                config.seed, "array-part-field", ordinal++, used_names);
            used_names.insert(first);
            const auto second = SyntheticName(
                config.seed, "array-part-field", ordinal++, used_names);
            used_names.insert(second);
            plan.split_field_names = {first, second};
            plan.split_init_name = SyntheticName(
                config.seed, "array-split-init", ordinal++, used_names);
            used_names.insert(plan.split_init_name);
            for (const auto& name : plan.split_field_names) {
                dex::FieldSpec part;
                part.name = name;
                part.type = field.type;
                part.access_flags = kPrivate | kStatic | kSynthetic | 0x0040U;
                klass.static_fields.push_back(std::move(part));
            }
            klass.direct_methods.push_back(
                BuildArraySplitInitializer(klass, plan));
            klass.direct_methods.push_back(
                BuildArraySplitElementAccessor(klass, plan));
        } else {
            klass.direct_methods.push_back(BuildArrayElementAccessor(klass, plan));
        }
        plans.push_back(std::move(plan));
    }
}


std::vector<std::uint8_t> ModelArrayProtection::RewriteArrayCallsites(
    const dex::DexFile& source, const std::vector<ArrayAccessorPlan>& plans,
    std::size_t& rewritten_count, ModelLoweringResult& report) {
    rewritten_count = 0U;
    if (plans.empty()) return source.Write();
    std::map<std::uint32_t, dex::CodePrefix> prefixes;
    const auto method_index = [&](const ArrayAccessorPlan& plan,
                                  std::string_view name,
                                  std::string_view proto)
        -> std::optional<std::uint32_t> {
        for (std::uint32_t index = 0U; index < source.methods().size(); ++index) {
            const auto& method = source.methods()[index];
            if (source.descriptor(method.class_idx) == plan.owner &&
                source.string(method.name_idx) == name &&
                source.proto_key(method.proto_idx) == proto) {
                return index;
            }
        }
        return std::nullopt;
    };
    for (const auto& plan : plans) {
        std::size_t plan_rewrites = 0U;
        std::optional<std::uint32_t> field_index;
        for (std::uint32_t index = 0U; index < source.fields().size(); ++index) {
            const auto& field = source.fields()[index];
            if (source.descriptor(field.class_idx) == plan.owner &&
                source.string(field.name_idx) == plan.field_name &&
                source.descriptor(field.type_idx) == plan.field_type) {
                field_index = index;
                break;
            }
        }
        if (!field_index.has_value()) continue;
        const auto accessor_proto = "(I)" + plan.element_type;
        const auto accessor_index = method_index(
            plan, plan.accessor_name, accessor_proto);
        if (!accessor_index.has_value() || *accessor_index > 0xffffU) continue;

        if (plan.split) {
            std::map<std::uint32_t, dex::CodePrefix> local_prefixes;
            bool unsafe_use = false;
            for (std::size_t class_index = 0U;
                 class_index < source.classes().size(); ++class_index) {
                const auto owner = source.descriptor(
                    source.classes()[class_index].class_idx);
                const auto& data = source.class_data(class_index);
                const auto collect = [&](const std::vector<dex::DexEncodedMethod>& methods) {
                    for (const auto& encoded : methods) {
                        if (encoded.code_off == 0U) continue;
                        const auto& id = source.methods().at(encoded.method_idx);
                        const auto name = source.string(id.name_idx);
                        if (owner == plan.owner && name == plan.split_init_name) {
                            continue;
                        }
                        const auto code = dex::DecodeCodeItem(
                            source, encoded.code_off);
                        for (std::size_t i = 0U; i < code.instructions.size(); ++i) {
                            const auto& instruction = code.instructions[i];
                            if ((instruction.opcode != 0x62U &&
                                 instruction.opcode != 0x69U) ||
                                instruction.width != 2U ||
                                instruction.code_units.size() < 2U ||
                                instruction.code_units[1U] != *field_index) {
                                continue;
                            }
                            if (instruction.opcode == 0x69U) {
                                if (!(owner == plan.owner && name == "<clinit>")) {
                                    unsafe_use = true;
                                }
                                continue;
                            }
                            if (instruction.opcode != 0x62U ||
                                owner != plan.owner || name == "<clinit>" ||
                                i + 1U >= code.instructions.size()) {
                                unsafe_use = true;
                                continue;
                            }
                            const auto& next = code.instructions[i + 1U];
                            const auto expected_aget = ArrayGetOpcode(
                                plan.element_type);
                            const auto array_register = static_cast<std::uint16_t>(
                                instruction.code_units.front() >> 8U);
                            if (next.opcode != expected_aget || next.width != 2U ||
                                next.offset != instruction.offset + instruction.width ||
                                next.code_units.size() < 2U ||
                                (next.code_units[1U] & 0xffU) != array_register) {
                                unsafe_use = true;
                                continue;
                            }
                            const auto result_register = static_cast<std::uint16_t>(
                                next.code_units.front() >> 8U);
                            if (result_register != array_register) {
                                unsafe_use = true;
                                continue;
                            }
                            const auto index_register = static_cast<std::uint16_t>(
                                next.code_units[1U] >> 8U);
                            std::vector<std::uint16_t> invoke;
                            if (index_register <= 0x0fU) {
                                invoke = {0x1071U,
                                          static_cast<std::uint16_t>(*accessor_index),
                                          index_register};
                            } else {
                                invoke = {0x0177U,
                                          static_cast<std::uint16_t>(*accessor_index),
                                          index_register};
                            }
                            const auto move_result = static_cast<std::uint8_t>(
                                TypeWordCount(plan.element_type) == 2U ? 0x0bU :
                                ((!plan.element_type.empty() &&
                                  (plan.element_type.front() == 'L' ||
                                   plan.element_type.front() == '[')) ?
                                     0x0cU : 0x0aU));
                            invoke.push_back(static_cast<std::uint16_t>(
                                move_result | (result_register << 8U)));
                            auto& prefix = local_prefixes[encoded.code_off];
                            prefix.code_off = encoded.code_off;
                            prefix.replacement_outs_size =
                                std::max<std::uint16_t>(code.outs_size, 1U);
                            prefix.linear_replacements.emplace(
                                instruction.offset,
                                std::vector<std::uint16_t>{
                                    static_cast<std::uint16_t>(
                                        0x13U | (array_register << 8U)),
                                    0U});
                            prefix.linear_replacements.emplace(
                                next.offset, std::move(invoke));
                            ++plan_rewrites;
                        }
                    }
                };
                collect(data.direct_methods);
                collect(data.virtual_methods);
            }
            if (unsafe_use || plan_rewrites == 0U) {
                continue;
            }
            for (auto& [code_off, local] : local_prefixes) {
                auto& output = prefixes[code_off];
                output.code_off = code_off;
                if (local.replacement_outs_size.has_value()) {
                    output.replacement_outs_size = std::max<std::uint16_t>(
                        output.replacement_outs_size.value_or(0U),
                        *local.replacement_outs_size);
                }
                for (auto& [offset, replacement] :
                     local.linear_replacements) {
                    const auto existing = output.linear_replacements.find(offset);
                    if (existing == output.linear_replacements.end()) {
                        output.linear_replacements.emplace(
                            offset, std::move(replacement));
                        continue;
                    }
                    if (!existing->second.empty() &&
                        existing->second.back() == 0x000eU &&
                        !replacement.empty() &&
                        replacement.back() == 0x000eU) {
                        existing->second.pop_back();
                        existing->second.insert(existing->second.end(),
                                                replacement.begin(),
                                                replacement.end());
                        continue;
                    }
                    if (existing->second != replacement) {
                        throw std::logic_error(
                            "conflicting array callsite rewrites");
                    }
                }
            }
            rewritten_count += plan_rewrites;
            ++report.split_arrays;
            ++report.pass_applications["data.array_splitting"];
            if (plan.virtualize) {
                ++report.virtualized_arrays;
                ++report.pass_applications["data.array_virtualization"];
            }
            continue;
        }

        std::map<std::uint32_t, dex::CodePrefix> local_prefixes;
        bool unsafe_use = false;
        for (std::size_t class_index = 0U;
             class_index < source.classes().size(); ++class_index) {
            const auto owner = source.descriptor(
                source.classes()[class_index].class_idx);
            const auto& data = source.class_data(class_index);
            const auto collect = [&](const std::vector<dex::DexEncodedMethod>& methods) {
                for (const auto& encoded : methods) {
                    if (encoded.code_off == 0U) continue;
                    const auto& method_id = source.methods().at(encoded.method_idx);
                    const auto method_name = source.string(method_id.name_idx);
                    if (owner == plan.owner &&
                        method_name == plan.accessor_name) {
                        continue;
                    }
                    const auto code = dex::DecodeCodeItem(source, encoded.code_off);
                    for (std::size_t i = 0U; i < code.instructions.size(); ++i) {
                        const auto& instruction = code.instructions[i];
                        if ((instruction.opcode != 0x62U &&
                             instruction.opcode != 0x69U) ||
                            instruction.width != 2U ||
                            instruction.code_units.size() < 2U ||
                            instruction.code_units[1U] != *field_index) {
                            continue;
                        }
                        if (instruction.opcode == 0x69U) {
                            continue; // backing-field assignment remains authoritative
                        }
                        if (instruction.opcode != 0x62U ||
                            i + 1U >= code.instructions.size()) {
                            unsafe_use = true;
                            continue;
                        }
                        const auto& next = code.instructions[i + 1U];
                        const auto array_register = static_cast<std::uint16_t>(
                            instruction.code_units.front() >> 8U);
                        if (next.width != 2U ||
                            next.offset != instruction.offset + instruction.width ||
                            next.code_units.size() < 2U ||
                            (next.code_units[1U] & 0xffU) != array_register) {
                            unsafe_use = true;
                            continue;
                        }
                        std::vector<std::uint16_t> replacement;
                        if (next.opcode == ArrayGetOpcode(plan.element_type)) {
                            const auto result_register = static_cast<std::uint16_t>(
                                next.code_units.front() >> 8U);
                            if (result_register != array_register) {
                                unsafe_use = true;
                                continue;
                            }
                            const auto index_register = static_cast<std::uint16_t>(
                                next.code_units[1U] >> 8U);
                            if (index_register <= 0x0fU) {
                                replacement = {
                                    0x1071U,
                                    static_cast<std::uint16_t>(*accessor_index),
                                    index_register};
                            } else {
                                replacement = {
                                    0x0177U,
                                    static_cast<std::uint16_t>(*accessor_index),
                                    index_register};
                            }
                            const auto move_result = static_cast<std::uint8_t>(
                                TypeWordCount(plan.element_type) == 2U ? 0x0bU :
                                ((!plan.element_type.empty() &&
                                  (plan.element_type.front() == 'L' ||
                                   plan.element_type.front() == '[')) ?
                                     0x0cU : 0x0aU));
                            replacement.push_back(static_cast<std::uint16_t>(
                                move_result | (result_register << 8U)));
                        } else {
                            unsafe_use = true;
                            continue;
                        }
                        auto& prefix = local_prefixes[encoded.code_off];
                        prefix.code_off = encoded.code_off;
                        prefix.replacement_outs_size = std::max<std::uint16_t>(
                            code.outs_size, 1U);
                        prefix.linear_replacements.emplace(
                            instruction.offset,
                            std::vector<std::uint16_t>{
                                static_cast<std::uint16_t>(
                                    0x13U | (array_register << 8U)),
                                0U});
                        prefix.linear_replacements.emplace(
                            next.offset, std::move(replacement));
                        ++plan_rewrites;
                    }
                }
            };
            collect(data.direct_methods);
            collect(data.virtual_methods);
        }
        if (unsafe_use || plan_rewrites == 0U) continue;
        for (auto& [code_off, local] : local_prefixes) {
            auto& output = prefixes[code_off];
            output.code_off = code_off;
            if (local.replacement_outs_size.has_value()) {
                output.replacement_outs_size = std::max<std::uint16_t>(
                    output.replacement_outs_size.value_or(0U),
                    *local.replacement_outs_size);
            }
            for (auto& [offset, replacement] : local.linear_replacements) {
                if (!output.linear_replacements.emplace(
                        offset, std::move(replacement)).second) {
                    throw std::logic_error(
                        "conflicting virtual array callsite rewrites");
                }
            }
        }
        rewritten_count += plan_rewrites;
        ++report.virtualized_arrays;
        ++report.pass_applications["data.array_virtualization"];
    }
    if (prefixes.empty()) return source.Write();
    std::vector<dex::CodePrefix> flattened;
    flattened.reserve(prefixes.size());
    for (auto& [code_off, prefix] : prefixes) {
        (void)code_off;
        if (!prefix.linear_replacements.empty()) {
            flattened.push_back(std::move(prefix));
        }
    }
    return dex::RewriteCodePrefixes(source, flattened);
}


} // namespace birch::guard::detail
