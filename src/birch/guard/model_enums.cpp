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

#include "model_enums.h"
#include "model_support.h"

namespace birch::guard::detail {
namespace {

std::optional<std::pair<std::uint16_t, std::int32_t>> DecodeIntConstant(
    const dex::DecodedInstruction& instruction) {
    if (instruction.opcode == 0x12U && instruction.width == 1U) {
        const auto destination = static_cast<std::uint16_t>(
            (instruction.code_units.front() >> 8U) & 0x0fU);
        auto value = static_cast<std::int32_t>(
            instruction.code_units.front() >> 12U);
        if ((value & 0x8) != 0) value |= ~0x0f;
        return std::pair{destination, value};
    }
    if (instruction.opcode == 0x13U && instruction.width == 2U) {
        return std::pair{
            static_cast<std::uint16_t>(instruction.code_units.front() >> 8U),
            static_cast<std::int32_t>(
                static_cast<std::int16_t>(instruction.code_units[1U]))};
    }
    if (instruction.opcode == 0x14U && instruction.width == 3U) {
        const auto bits = static_cast<std::uint32_t>(instruction.code_units[1U]) |
            static_cast<std::uint32_t>(instruction.code_units[2U]) << 16U;
        return std::pair{
            static_cast<std::uint16_t>(instruction.code_units.front() >> 8U),
            static_cast<std::int32_t>(bits)};
    }
    return std::nullopt;
}


} // namespace

void ModelEnumProtection::AddEnumProtocol(dex::ClassSpec& klass, const GuardConfig& config,
                     std::vector<EnumLoweringPlan>& plans) {
    const auto& pass = config.passes.at("data.enum_lowering");
    if (!pass.enabled || (klass.access_flags & kEnum) == 0U ||
        !Selected(pass, config.seed, klass.descriptor, 0x454e554dU)) {
        return;
    }
    std::set<std::string, std::less<>> used_names;
    for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (const auto& method : *methods) used_names.insert(method.name);
    }
    std::size_t enum_value_count = 0U;
    for (const auto& field : klass.static_fields) {
        used_names.insert(field.name);
        if (field.type == klass.descriptor &&
            (field.access_flags & kEnum) != 0U) {
            ++enum_value_count;
        }
    }
    if (enum_value_count == 0U || enum_value_count > 0x7fffU) return;
    const auto name = SyntheticName(config.seed, "enum-code", 0U, used_names);
    used_names.insert(name);
    const auto table_name = SyntheticName(
        config.seed, "enum-table", 1U, used_names);
    auto state = utils::StableHash64(
        klass.descriptor, pass.seed.value_or(config.seed) ^ 0x656e756d636f6465ULL);
    const auto multiplier = static_cast<std::uint32_t>(state) | 1U;
    state ^= state >> 29U;
    auto xor_mask = static_cast<std::int32_t>(
        static_cast<std::int16_t>(state & 0xffffU));
    if (xor_mask == 0) xor_mask = 0x5a5b;

    dex::FieldSpec table;
    table.name = table_name;
    table.type = "[I";
    table.access_flags = 0x104aU; // private static volatile synthetic
    klass.static_fields.push_back(std::move(table));

    dex::MethodSpec method;
    method.name = name;
    method.return_type = "I";
    method.access_flags = 0x1031U; // public final synchronized synthetic
    method.body.registers_size = 5U;
    method.body.ins_size = 1U;
    method.body.outs_size = 1U;
    auto& code = method.body.code_units;
    code.insert(code.end(), {0x0062U, 0U}); // sget-object v0, encoded table
    method.body.references.push_back({
        dex::FieldReference{klass.descriptor, table_name, "[I"}, 1U, false});
    const auto initialized_branch = static_cast<std::uint32_t>(code.size());
    code.insert(code.end(), {0x0039U, 0U}); // if-nez v0, lookup
    code.insert(code.end(), {
        0x0113U, static_cast<std::uint16_t>(enum_value_count),
        0x1023U, 0U, // new-array v0, v1, int[]
    });
    method.body.references.push_back({
        dex::TypeReference{"[I"},
        static_cast<std::uint32_t>(code.size() - 1U), false});
    for (std::size_t ordinal = 0U; ordinal < enum_value_count; ++ordinal) {
        const auto encoded = static_cast<std::uint32_t>(ordinal) * multiplier ^
                             static_cast<std::uint32_t>(xor_mask);
        code.insert(code.end(), {
            0x0214U, static_cast<std::uint16_t>(encoded),
            static_cast<std::uint16_t>(encoded >> 16U),
            0x0313U, static_cast<std::uint16_t>(ordinal),
            0x024bU, 0x0300U, // aput v2, v0, v3
        });
    }
    code.insert(code.end(), {0x0069U, 0U}); // sput-object v0, encoded table
    method.body.references.push_back({
        dex::FieldReference{klass.descriptor, table_name, "[I"},
        static_cast<std::uint32_t>(code.size() - 1U), false});
    const auto lookup_offset = static_cast<std::uint32_t>(code.size());
    code[initialized_branch + 1U] = static_cast<std::uint16_t>(
        lookup_offset - initialized_branch);
    AppendInvoke35c(code, 0x6eU, {4U}, method.body,
                    {"Ljava/lang/Enum;", "ordinal", "I", {}});
    code.insert(code.end(), {
        0x010aU, // move-result v1
        0x0044U, 0x0100U, // aget v0, v0, v1
        0x000fU,
    });
    klass.virtual_methods.push_back(std::move(method));
    plans.push_back({klass.descriptor, name, multiplier, xor_mask});
}


std::vector<std::uint8_t> ModelEnumProtection::RewriteEnumCallsites(
    const dex::DexFile& source, const std::vector<EnumLoweringPlan>& plans,
    ModelLoweringResult& report) {
    if (plans.empty()) return source.Write();
    std::map<std::uint32_t, dex::CodePrefix> prefixes;
    for (const auto& plan : plans) {
        std::optional<std::uint32_t> helper_index;
        for (std::uint32_t index = 0U; index < source.methods().size(); ++index) {
            const auto& method = source.methods()[index];
            if (source.descriptor(method.class_idx) == plan.owner &&
                source.string(method.name_idx) == plan.method_name &&
                source.proto_key(method.proto_idx) == "()I") {
                helper_index = index;
                break;
            }
        }
        if (!helper_index.has_value() || *helper_index > 0xffffU) continue;
        std::size_t rewritten = 0U;
        for (std::size_t class_index = 0U;
             class_index < source.classes().size(); ++class_index) {
            const auto& data = source.class_data(class_index);
            const auto collect = [&](const std::vector<dex::DexEncodedMethod>& methods) {
                for (const auto& encoded : methods) {
                    if (encoded.code_off == 0U) continue;
                    const auto code = dex::DecodeCodeItem(source, encoded.code_off);
                    for (std::size_t i = 0U; i + 3U < code.instructions.size(); ++i) {
                        const auto& invoke = code.instructions[i];
                        if ((invoke.opcode != 0x6eU && invoke.opcode != 0x74U) ||
                            invoke.code_units.size() < 3U) {
                            continue;
                        }
                        const auto target_index = invoke.code_units[1U];
                        if (target_index >= source.methods().size()) continue;
                        const auto& target = source.methods()[target_index];
                        const auto target_owner = source.descriptor(target.class_idx);
                        if (source.string(target.name_idx) != "ordinal" ||
                            source.proto_key(target.proto_idx) != "()I") {
                            continue;
                        }
                        const auto argument_count = invoke.opcode == 0x6eU ?
                            static_cast<std::uint16_t>(
                                invoke.code_units.front() >> 12U) :
                            static_cast<std::uint16_t>(
                                invoke.code_units.front() >> 8U);
                        if (argument_count != 1U) continue;
                        const auto receiver = invoke.opcode == 0x6eU ?
                            static_cast<std::uint16_t>(
                                invoke.code_units[2U] & 0x0fU) :
                            invoke.code_units[2U];
                        bool receiver_is_enum = target_owner == plan.owner;
                        if (!receiver_is_enum && target_owner == "Ljava/lang/Enum;" &&
                            i != 0U) {
                            const auto& producer = code.instructions[i - 1U];
                            if (producer.opcode == 0x62U && producer.width == 2U &&
                                producer.code_units.size() >= 2U &&
                                (producer.code_units.front() >> 8U) == receiver) {
                                const auto field_index = producer.code_units[1U];
                                if (field_index < source.fields().size()) {
                                    const auto& field = source.fields()[field_index];
                                    receiver_is_enum =
                                        source.descriptor(field.class_idx) == plan.owner &&
                                        source.descriptor(field.type_idx) == plan.owner;
                                }
                            }
                        }
                        if (!receiver_is_enum) continue;
                        const auto& move_result = code.instructions[i + 1U];
                        const auto& constant = code.instructions[i + 2U];
                        const auto& branch = code.instructions[i + 3U];
                        if (move_result.opcode != 0x0aU ||
                            move_result.width != 1U ||
                            (branch.opcode != 0x32U && branch.opcode != 0x33U)) {
                            continue;
                        }
                        const auto decoded_constant = DecodeIntConstant(constant);
                        if (!decoded_constant.has_value()) continue;
                        const auto result_register = static_cast<std::uint16_t>(
                            move_result.code_units.front() >> 8U);
                        const auto branch_first = branch.code_units.front();
                        const auto first_register = static_cast<std::uint16_t>(
                            (branch_first >> 8U) & 0x0fU);
                        const auto second_register = static_cast<std::uint16_t>(
                            branch_first >> 12U);
                        if (!((first_register == result_register &&
                               second_register == decoded_constant->first) ||
                              (second_register == result_register &&
                               first_register == decoded_constant->first))) {
                            continue;
                        }
                        auto replacement_invoke = invoke.code_units;
                        replacement_invoke[1U] = static_cast<std::uint16_t>(
                            *helper_index);
                        const auto encoded_value =
                            static_cast<std::uint32_t>(decoded_constant->second) *
                                plan.multiplier ^
                            static_cast<std::uint32_t>(plan.xor_mask);
                        auto& prefix = prefixes[encoded.code_off];
                        prefix.code_off = encoded.code_off;
                        prefix.linear_replacements.emplace(
                            invoke.offset, std::move(replacement_invoke));
                        prefix.linear_replacements.emplace(
                            constant.offset,
                            std::vector<std::uint16_t>{
                                static_cast<std::uint16_t>(
                                    0x14U | (decoded_constant->first << 8U)),
                                static_cast<std::uint16_t>(encoded_value),
                                static_cast<std::uint16_t>(encoded_value >> 16U)});
                        ++rewritten;
                    }
                }
            };
            collect(data.direct_methods);
            collect(data.virtual_methods);
        }
        if (rewritten != 0U) {
            ++report.lowered_enums;
            report.pass_applications["data.enum_lowering"] += rewritten;
        }
    }
    if (prefixes.empty()) return source.Write();
    std::vector<dex::CodePrefix> flattened;
    flattened.reserve(prefixes.size());
    for (auto& [code_off, prefix] : prefixes) {
        (void)code_off;
        flattened.push_back(std::move(prefix));
    }
    return dex::RewriteCodePrefixes(source, flattened);
}


} // namespace birch::guard::detail
