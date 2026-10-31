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

#include "model_support.h"

namespace birch::guard::detail {

ReturnSequence BuildReturnSequence(std::string_view return_type) {
    if (return_type == "V") return {{0x000eU}, 1U};
    if (return_type == "J" || return_type == "D") {
        return {{0x000bU, 0x0010U}, 2U};
    }
    if (!return_type.empty() &&
        (return_type.front() == 'L' || return_type.front() == '[')) {
        return {{0x000cU, 0x0011U}, 1U};
    }
    return {{0x000aU, 0x000fU}, 1U};
}


std::uint16_t TypeWordCount(std::string_view type) {
    return type == "J" || type == "D" ? 2U : 1U;
}


void ValidateInvokeRegisters(
    std::uint8_t opcode, const std::vector<std::uint16_t>& registers,
    const dex::MethodReference& reference) {
    if (opcode < 0x6eU || opcode > 0x72U) {
        throw std::invalid_argument("unsupported invoke opcode");
    }
    std::uint32_t expected = opcode == 0x71U ? 0U : 1U;
    for (const auto& parameter : reference.parameter_types) {
        expected += TypeWordCount(parameter);
    }
    if (registers.size() != expected) {
        throw std::invalid_argument(
            "invoke register words disagree with target prototype");
    }
}


void AppendInvoke35c(std::vector<std::uint16_t>& code, std::uint8_t opcode,
                     const std::vector<std::uint16_t>& registers,
                     dex::MethodBodySpec& body,
                     dex::MethodReference reference) {
    ValidateInvokeRegisters(opcode, registers, reference);
    if (registers.size() > 5U ||
        std::any_of(registers.begin(), registers.end(),
                    [](const auto value) { return value > 0x0fU; })) {
        throw std::invalid_argument("invoke-35c register list is not encodable");
    }
    const auto at = static_cast<std::uint32_t>(code.size());
    const auto fifth = registers.size() == 5U ? registers[4U] : 0U;
    code.push_back(static_cast<std::uint16_t>(
        opcode | (fifth << 8U) | (registers.size() << 12U)));
    code.push_back(0U);
    std::uint16_t packed = 0U;
    for (std::size_t i = 0U; i < std::min<std::size_t>(4U, registers.size()); ++i) {
        packed = static_cast<std::uint16_t>(packed | (registers[i] << (i * 4U)));
    }
    code.push_back(packed);
    body.references.push_back({std::move(reference), at + 1U, false});
}


void AppendInvoke(std::vector<std::uint16_t>& code, std::uint8_t opcode,
                  const std::vector<std::uint16_t>& registers,
                  dex::MethodBodySpec& body,
                  dex::MethodReference reference) {
    ValidateInvokeRegisters(opcode, registers, reference);
    if (registers.size() <= 5U &&
        std::all_of(registers.begin(), registers.end(),
                    [](const auto value) { return value <= 0x0fU; })) {
        AppendInvoke35c(code, opcode, registers, body, std::move(reference));
        return;
    }
    if (registers.empty() || registers.size() > 0xffU ||
        !std::equal(registers.begin() + 1U, registers.end(),
                    registers.begin(),
                    [](const auto next, const auto previous) {
                        return next == previous + 1U;
                    })) {
        throw std::invalid_argument(
            "invoke/range requires a non-empty contiguous register window");
    }
    std::uint8_t range_opcode = 0U;
    switch (opcode) {
        case 0x6eU: range_opcode = 0x74U; break;
        case 0x6fU: range_opcode = 0x75U; break;
        case 0x70U: range_opcode = 0x76U; break;
        case 0x71U: range_opcode = 0x77U; break;
        case 0x72U: range_opcode = 0x78U; break;
        default:
            throw std::invalid_argument("invoke opcode has no range form");
    }
    const auto at = static_cast<std::uint32_t>(code.size());
    code.push_back(static_cast<std::uint16_t>(
        range_opcode |
        (static_cast<std::uint16_t>(registers.size()) << 8U)));
    code.push_back(0U);
    code.push_back(registers.front());
    body.references.push_back({std::move(reference), at + 1U, false});
}


dex::MethodBodySpec BuildStaticForwardBody(
    std::string_view return_type, std::uint16_t input_words,
    dex::MethodReference target) {
    const auto returns = BuildReturnSequence(return_type);
    dex::MethodBodySpec body;
    body.ins_size = input_words;
    body.registers_size = static_cast<std::uint16_t>(
        returns.local_words + input_words);
    body.outs_size = input_words;
    const auto arguments = InputRegisters(returns.local_words, input_words);
    AppendInvoke(body.code_units, 0x71U, arguments, body,
                 std::move(target));
    body.code_units.insert(body.code_units.end(), returns.code.begin(),
                           returns.code.end());
    return body;
}


std::vector<std::uint16_t> InputRegisters(std::uint16_t base,
                                          std::uint16_t count) {
    std::vector<std::uint16_t> result;
    result.reserve(count);
    for (std::uint16_t i = 0U; i < count; ++i) {
        result.push_back(static_cast<std::uint16_t>(base + i));
    }
    return result;
}


std::string SyntheticName(std::uint64_t seed, std::string_view role,
                          std::size_t ordinal,
                          const std::set<std::string, std::less<>>& used) {
    for (std::uint32_t attempt = 0U; attempt < 1024U; ++attempt) {
        std::ostringstream stream;
        stream << "$b" << std::hex << std::setfill('0') << std::setw(8)
               << static_cast<std::uint32_t>(utils::StableHash64(
                      std::string(role) + std::to_string(ordinal),
                      seed + attempt));
        auto value = stream.str();
        if (!used.contains(value)) return value;
    }
    throw std::runtime_error("cannot allocate a collision-free synthetic method name");
}


std::string ReflectionProxyName(
    std::uint64_t seed, std::size_t ordinal,
    const std::set<std::string, std::less<>>& used) {
    for (std::uint32_t attempt = 0U; attempt < 1024U; ++attempt) {
        std::ostringstream stream;
        stream << "$br$" << std::hex << std::setfill('0') << std::setw(8)
               << static_cast<std::uint32_t>(utils::StableHash64(
                      "reflection-proxy:" + std::to_string(ordinal),
                      seed + attempt));
        auto value = stream.str();
        if (!used.contains(value)) return value;
    }
    throw std::runtime_error(
        "cannot allocate a collision-free reflection proxy method name");
}


dex::MethodReference MethodReferenceFor(const dex::ClassSpec& klass,
                                        const dex::MethodSpec& method) {
    return {klass.descriptor, method.name, method.return_type,
            method.parameter_types};
}


dex::MethodBodySpec BuildWrapperBody(const dex::ClassSpec& klass,
                                     const dex::MethodSpec& original,
                                     const dex::MethodSpec& target,
                                     std::optional<std::uint8_t> depth,
                                     std::optional<std::string_view> target_owner) {
    const auto is_static = (original.access_flags & kStatic) != 0U;
    const auto returns = BuildReturnSequence(original.return_type);
    dex::MethodBodySpec body;
    const auto locals = returns.local_words;
    body.ins_size = original.body.ins_size;
    body.registers_size = static_cast<std::uint16_t>(locals + body.ins_size);
    auto arguments = InputRegisters(locals, body.ins_size);
    if (depth.has_value()) {
        body.code_units.push_back(static_cast<std::uint16_t>(
            0x12U | (static_cast<std::uint16_t>(*depth & 0x0fU) << 12U)));
        arguments.push_back(0U);
    }
    body.outs_size = static_cast<std::uint16_t>(arguments.size());
    AppendInvoke(body.code_units, is_static ? 0x71U : 0x70U, arguments,
                 body, {std::string(target_owner.value_or(klass.descriptor)),
                        target.name, target.return_type,
                        target.parameter_types});
    body.code_units.insert(body.code_units.end(), returns.code.begin(),
                           returns.code.end());
    return body;
}


bool HasTransformableBody(const dex::MethodSpec& method) {
    if (method.name == "<init>" || method.name == "<clinit>" ||
        (method.access_flags & (kNative | kAbstract)) != 0U ||
        method.body.code_units.empty()) {
        return false;
    }
    return method.body.ins_size <= 0xffU;
}


std::size_t BodyInstructionWidth(const dex::MethodBodySpec& body,
                                 std::size_t cursor) {
    if (cursor >= body.code_units.size()) return 0U;
    const auto opcode = static_cast<std::uint8_t>(
        body.code_units[cursor] & 0xffU);
    std::size_t width = 1U;
    if (opcode == 0x00U) {
        const auto ident = body.code_units[cursor];
        if (ident == 0x0100U && cursor + 1U < body.code_units.size()) {
            width = 4U + static_cast<std::size_t>(
                body.code_units[cursor + 1U]) * 2U;
        } else if (ident == 0x0200U &&
                   cursor + 1U < body.code_units.size()) {
            width = 2U + static_cast<std::size_t>(
                body.code_units[cursor + 1U]) * 4U;
        } else if (ident == 0x0300U &&
                   cursor + 3U < body.code_units.size()) {
            const auto element_width = body.code_units[cursor + 1U];
            const auto count = static_cast<std::uint32_t>(
                body.code_units[cursor + 2U]) |
                static_cast<std::uint32_t>(body.code_units[cursor + 3U]) << 16U;
            width = 4U +
                (static_cast<std::size_t>(element_width) * count + 1U) / 2U;
        }
    } else if (opcode == 0x18U) {
        width = 5U;
    } else if (opcode == 0x03U || opcode == 0x06U || opcode == 0x09U ||
               opcode == 0x14U || opcode == 0x17U || opcode == 0x1bU ||
               (opcode >= 0x24U && opcode <= 0x26U) || opcode == 0x2aU ||
               opcode == 0x2bU || opcode == 0x2cU ||
               (opcode >= 0x6eU && opcode <= 0x72U) ||
               (opcode >= 0x74U && opcode <= 0x78U) ||
               opcode == 0xfcU || opcode == 0xfdU) {
        width = 3U;
    } else if (opcode == 0xfaU || opcode == 0xfbU) {
        width = 4U;
    } else if (opcode == 0x02U || opcode == 0x05U || opcode == 0x08U ||
               opcode == 0x13U || opcode == 0x15U || opcode == 0x16U ||
               opcode == 0x19U || opcode == 0x1aU || opcode == 0x1cU ||
               opcode == 0x1fU || opcode == 0x20U || opcode == 0x22U ||
               opcode == 0x23U || opcode == 0x29U ||
               (opcode >= 0x2dU && opcode <= 0x3dU) ||
               (opcode >= 0x44U && opcode <= 0x6dU) ||
               (opcode >= 0x90U && opcode <= 0xafU) ||
               (opcode >= 0xd0U && opcode <= 0xe2U) || opcode == 0xfeU ||
               opcode == 0xffU) {
        width = 2U;
    }
    return cursor + width <= body.code_units.size() ? width : 0U;
}


bool HasInvokeSuper(const dex::MethodSpec& method) {
    for (std::size_t cursor = 0U; cursor < method.body.code_units.size();) {
        const auto opcode = static_cast<std::uint8_t>(
            method.body.code_units[cursor] & 0xffU);
        if (opcode == 0x6fU || opcode == 0x75U) return true;
        const auto width = BodyInstructionWidth(method.body, cursor);
        if (width == 0U || cursor + width > method.body.code_units.size()) break;
        cursor += width;
    }
    return false;
}


bool Selected(const PassConfig& pass, std::uint64_t global_seed,
              std::string_view key, std::uint64_t salt) {
    if (!pass.enabled) return false;
    const auto hash = utils::StableHash64(
        key, pass.seed.value_or(global_seed) ^ salt);
    const auto sample = static_cast<double>(hash >> 11U) /
                        static_cast<double>(std::uint64_t{1U} << 53U);
    return sample <= pass.intensity;
}


std::string SyntheticClassDescriptor(
    std::string_view role, std::string_view source, std::uint64_t seed,
    std::size_t ordinal, const std::set<std::string, std::less<>>& used) {
    for (std::uint32_t attempt = 0U; attempt < 1024U; ++attempt) {
        const auto material = std::string(role) + ":" + std::string(source) +
            ":" + std::to_string(ordinal) + ":" + std::to_string(attempt);
        const auto package_hash = utils::StableHash64(
            material, seed ^ 0xd6e8feb86659fd93ULL);
        const auto class_hash = utils::StableHash64(
            material, seed ^ 0xa0761d6478bd642fULL);
        std::ostringstream stream;
        // Keep high hash/seed bits. Truncation silently reduced the namespace
        // and allowed independent DEX shards to allocate identical definitions.
        stream << 'L' << 'a' << std::hex << std::setfill('0') << std::setw(16)
               << package_hash << "/a" << std::setw(16) << class_hash << ';';
        auto descriptor = stream.str();
        if (!used.contains(descriptor)) return descriptor;
    }
    throw std::runtime_error("cannot allocate a collision-free synthetic class");
}


std::string MethodIdentity(const dex::MethodReference& reference) {
    std::string key = reference.owner + "->" + reference.name + "(";
    for (const auto& parameter : reference.parameter_types) key += parameter;
    key += ")" + reference.return_type;
    return key;
}


std::vector<std::uint16_t> ModelInvokeRegisters(
    const dex::MethodBodySpec& body, std::uint32_t instruction_offset) {
    if (instruction_offset >= body.code_units.size()) return {};
    const auto first = body.code_units[instruction_offset];
    const auto opcode = static_cast<std::uint8_t>(first);
    if (opcode >= 0x6eU && opcode <= 0x72U) {
        if (instruction_offset + 2U >= body.code_units.size()) return {};
        const auto count = static_cast<std::size_t>(first >> 12U);
        if (count > 5U) return {};
        const auto packed = body.code_units[instruction_offset + 2U];
        const std::array<std::uint16_t, 5U> registers{
            static_cast<std::uint16_t>(packed & 0x0fU),
            static_cast<std::uint16_t>((packed >> 4U) & 0x0fU),
            static_cast<std::uint16_t>((packed >> 8U) & 0x0fU),
            static_cast<std::uint16_t>((packed >> 12U) & 0x0fU),
            static_cast<std::uint16_t>((first >> 8U) & 0x0fU),
        };
        return {registers.begin(), registers.begin() + count};
    }
    if (opcode >= 0x74U && opcode <= 0x78U) {
        if (instruction_offset + 2U >= body.code_units.size()) return {};
        const auto count = static_cast<std::uint16_t>(first >> 8U);
        const auto base = body.code_units[instruction_offset + 2U];
        std::vector<std::uint16_t> registers;
        registers.reserve(count);
        for (std::uint16_t word = 0U; word < count; ++word) {
            registers.push_back(static_cast<std::uint16_t>(base + word));
        }
        return registers;
    }
    return {};
}


std::vector<std::uint8_t> CompactDex(const dex::DexFile& source) {
    dex::DexClassCloner cloner(source);
    dex::DexBuilder builder(source.version());
    for (std::size_t index = 0U; index < source.classes().size(); ++index) {
        builder.AddClass(cloner.Clone(index));
    }
    return builder.Build();
}


} // namespace birch::guard::detail
