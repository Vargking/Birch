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

#include "model_reflection.h"
#include "model_support.h"
#include "model_strings.h"

namespace birch::guard::detail {
namespace {

struct ReflectionArgument {
    ReflectionStringKind kind{};
    std::size_t register_ordinal{};
};


std::optional<ReflectionArgument> ReflectionArgumentFor(
    const dex::DexFile& dex_file, const dex::DecodedInstruction& instruction) {
    if (instruction.opcode < 0x6eU || instruction.opcode > 0x78U ||
        instruction.opcode == 0x73U || instruction.width < 3U) {
        return std::nullopt;
    }
    const auto method_index = instruction.code_units.at(1U);
    if (method_index >= dex_file.methods().size()) return std::nullopt;
    const auto& method = dex_file.methods().at(method_index);
    const auto owner = dex_file.descriptor(method.class_idx);
    const auto name = dex_file.string(method.name_idx);
    const auto proto = dex_file.proto_key(method.proto_idx);
    if (owner == "Ljava/lang/Class;" && name == "forName" &&
        (proto == "(Ljava/lang/String;)Ljava/lang/Class;" ||
         proto == "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;")) {
        return ReflectionArgument{ReflectionStringKind::Class, 0U};
    }
    if (owner == "Ljava/lang/ClassLoader;" && name == "loadClass" &&
        proto == "(Ljava/lang/String;)Ljava/lang/Class;") {
        return ReflectionArgument{ReflectionStringKind::Class, 1U};
    }
    if (owner == "Ljava/lang/Class;" &&
        (name == "getMethod" || name == "getDeclaredMethod") &&
        (proto == "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;")) {
        return ReflectionArgument{ReflectionStringKind::Method, 1U};
    }
    if (owner == "Ljava/lang/Class;" &&
        (name == "getField" || name == "getDeclaredField") &&
        proto == "(Ljava/lang/String;)Ljava/lang/reflect/Field;") {
        return ReflectionArgument{ReflectionStringKind::Field, 1U};
    }
    if (owner == "Ljava/lang/Enum;" && name == "valueOf" &&
        proto == "(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;") {
        return ReflectionArgument{ReflectionStringKind::Field, 1U};
    }
    if (owner == "Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;" ||
        owner == "Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;" ||
        owner == "Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;") {
        if (name == "newUpdater") {
            const auto ordinal = owner ==
                "Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;" ? 2U : 1U;
            return ReflectionArgument{ReflectionStringKind::Field, ordinal};
        }
    }
    if (owner == "Ljava/lang/invoke/MethodHandles$Lookup;" &&
        (name == "findVirtual" || name == "findStatic" ||
         name == "findSpecial" || name == "findConstructor")) {
        return name == "findConstructor" ? std::nullopt :
            std::optional<ReflectionArgument>{
                ReflectionArgument{ReflectionStringKind::Method, 2U}};
    }
    if (owner == "Ljava/lang/invoke/MethodHandles$Lookup;" &&
        (name == "findGetter" || name == "findSetter" ||
         name == "findStaticGetter" || name == "findStaticSetter")) {
        return ReflectionArgument{ReflectionStringKind::Field, 2U};
    }
    return std::nullopt;
}


std::vector<std::uint16_t> InvokeRegisters(
    const dex::DecodedInstruction& instruction) {
    std::vector<std::uint16_t> result;
    if (instruction.opcode >= 0x6eU && instruction.opcode <= 0x72U) {
        const auto count = static_cast<std::size_t>(
            instruction.code_units.front() >> 12U);
        if (count > 5U) return {};
        const auto packed = instruction.code_units.at(2U);
        const std::array<std::uint16_t, 5U> registers{
            static_cast<std::uint16_t>(packed & 0x0fU),
            static_cast<std::uint16_t>((packed >> 4U) & 0x0fU),
            static_cast<std::uint16_t>((packed >> 8U) & 0x0fU),
            static_cast<std::uint16_t>((packed >> 12U) & 0x0fU),
            static_cast<std::uint16_t>((instruction.code_units.front() >> 8U) &
                                       0x0fU),
        };
        result.assign(registers.begin(), registers.begin() + count);
    } else if (instruction.opcode >= 0x74U && instruction.opcode <= 0x78U) {
        const auto count = static_cast<std::uint16_t>(
            instruction.code_units.front() >> 8U);
        const auto first = instruction.code_units.at(2U);
        result.reserve(count);
        for (std::uint16_t offset = 0U; offset < count; ++offset) {
            result.push_back(static_cast<std::uint16_t>(first + offset));
        }
    }
    return result;
}


std::optional<std::uint16_t> DestinationRegister(
    const dex::DecodedInstruction& instruction) {
    const auto opcode = instruction.opcode;
    const auto first = instruction.code_units.front();
    if (opcode == 0x01U || opcode == 0x04U || opcode == 0x07U ||
        opcode == 0x20U || opcode == 0x21U || opcode == 0x23U ||
        (opcode >= 0x7bU && opcode <= 0x8fU) ||
        (opcode >= 0xb0U && opcode <= 0xd7U)) {
        return static_cast<std::uint16_t>((first >> 8U) & 0x0fU);
    }
    if (opcode == 0x02U || opcode == 0x05U || opcode == 0x08U ||
        (opcode >= 0x0aU && opcode <= 0x0dU) ||
        (opcode >= 0x12U && opcode <= 0x1cU) || opcode == 0x22U ||
        (opcode >= 0x2dU && opcode <= 0x31U) ||
        (opcode >= 0x44U && opcode <= 0x4aU) ||
        (opcode >= 0x60U && opcode <= 0x66U) ||
        (opcode >= 0x90U && opcode <= 0xafU) ||
        (opcode >= 0xd8U && opcode <= 0xe2U)) {
        return static_cast<std::uint16_t>(first >> 8U);
    }
    if (opcode == 0x03U || opcode == 0x06U || opcode == 0x09U) {
        return instruction.code_units.size() > 1U ?
            std::optional<std::uint16_t>{instruction.code_units.at(1U)} :
            std::nullopt;
    }
    if (opcode >= 0x52U && opcode <= 0x58U) {
        return static_cast<std::uint16_t>((first >> 8U) & 0x0fU);
    }
    return std::nullopt;
}


std::optional<std::string> ReflectionReplacement(
    std::string_view value, ReflectionStringKind kind,
    const ReflectionRenamePlan& plan) {
    const auto lookup = [&](const auto& values) -> std::optional<std::string> {
        const auto found = values.find(value);
        return found == values.end() ? std::nullopt :
            std::optional<std::string>{found->second};
    };
    if (kind == ReflectionStringKind::Method) return lookup(plan.methods);
    if (kind == ReflectionStringKind::Field) return lookup(plan.fields);
    if (const auto direct = lookup(plan.classes); direct.has_value()) return direct;
    auto descriptor = std::string("L") + std::string(value) + ";";
    std::replace(descriptor.begin(), descriptor.end(), '.', '/');
    const auto found = plan.classes.find(descriptor);
    if (found == plan.classes.end()) return std::nullopt;
    auto dotted = found->second.substr(1U, found->second.size() - 2U);
    std::replace(dotted.begin(), dotted.end(), '/', '.');
    return dotted;
}


bool IsIndirectReflectionTarget(const dex::MethodReference& reference) {
    if (reference.owner == "Ljava/lang/Class;") {
        return reference.name == "forName" ||
            reference.name == "getMethod" ||
            reference.name == "getDeclaredMethod" ||
            reference.name == "getField" ||
            reference.name == "getDeclaredField";
    }
    if (reference.owner == "Ljava/lang/ClassLoader;") {
        return reference.name == "loadClass";
    }
    if (reference.owner == "Ljava/lang/Enum;") {
        return reference.name == "valueOf";
    }
    if (reference.owner ==
            "Ljava/lang/invoke/MethodHandles$Lookup;") {
        return reference.name == "findVirtual" ||
            reference.name == "findStatic" ||
            reference.name == "findSpecial" ||
            reference.name == "findConstructor" ||
            reference.name == "findGetter" ||
            reference.name == "findSetter" ||
            reference.name == "findStaticGetter" ||
            reference.name == "findStaticSetter";
    }
    const auto atomic_updater =
        reference.owner ==
            "Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;" ||
        reference.owner ==
            "Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;" ||
        reference.owner ==
            "Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;";
    return atomic_updater && reference.name == "newUpdater";
}


std::uint8_t InvokeBaseOpcode(std::uint8_t opcode) {
    if (opcode >= 0x6eU && opcode <= 0x72U) return opcode;
    if (opcode >= 0x74U && opcode <= 0x78U) {
        return static_cast<std::uint8_t>(opcode - 6U);
    }
    return 0U;
}


void AppendInvokeKind(std::vector<std::uint16_t>& code, std::uint8_t opcode,
                      const std::vector<std::uint16_t>& registers,
                      dex::MethodBodySpec& body,
                      dex::MethodReference reference) {
    if (registers.size() <= 5U &&
        std::all_of(registers.begin(), registers.end(),
                    [](const auto value) { return value <= 0x0fU; })) {
        AppendInvoke35c(code, opcode, registers, body, std::move(reference));
        return;
    }
    if (registers.empty() || registers.size() > 0xffU ||
        !std::equal(registers.begin() + 1U, registers.end(),
                    registers.begin(), [](const auto next, const auto previous) {
                        return next == previous + 1U;
                    })) {
        throw std::invalid_argument(
            "reflection proxy invoke/range requires contiguous inputs");
    }
    const auto at = static_cast<std::uint32_t>(code.size());
    code.push_back(static_cast<std::uint16_t>(
        static_cast<std::uint8_t>(opcode + 6U) |
        (static_cast<std::uint16_t>(registers.size()) << 8U)));
    code.push_back(0U);
    code.push_back(registers.front());
    body.references.push_back({std::move(reference), at + 1U, false});
}


dex::MethodSpec BuildReflectionProxyMethod(
    std::string name, const dex::MethodReference& target,
    std::uint8_t invoke_opcode) {
    const auto is_static = invoke_opcode == 0x71U;
    dex::MethodSpec proxy;
    proxy.name = std::move(name);
    proxy.return_type = target.return_type;
    proxy.parameter_types = target.parameter_types;
    if (!is_static) {
        proxy.parameter_types.insert(proxy.parameter_types.begin(), target.owner);
    }
    proxy.access_flags = 0x1009U; // public static synthetic
    const auto returns = BuildReturnSequence(proxy.return_type);
    std::uint16_t input_words = 0U;
    for (const auto& type : proxy.parameter_types) {
        input_words = static_cast<std::uint16_t>(
            input_words + TypeWordCount(type));
    }
    proxy.body.ins_size = input_words;
    proxy.body.outs_size = input_words;
    proxy.body.registers_size = static_cast<std::uint16_t>(
        returns.local_words + input_words);
    const auto registers = InputRegisters(returns.local_words, input_words);
    AppendInvokeKind(proxy.body.code_units, invoke_opcode, registers,
                     proxy.body, target);
    proxy.body.code_units.insert(proxy.body.code_units.end(),
                                 returns.code.begin(), returns.code.end());
    return proxy;
}


} // namespace

ReflectionSiteMap ModelReflectionProtection::BuildReflectionSiteMap(
    const dex::DexFile& source, const ReflectionRenamePlan& plan) {
    ReflectionSiteMap result;
    for (std::size_t class_index = 0U; class_index < source.classes().size();
         ++class_index) {
        const auto owner = source.descriptor(source.classes()[class_index].class_idx);
        const auto& data = source.class_data(class_index);
        const auto collect = [&](const std::vector<dex::DexEncodedMethod>& methods) {
            for (const auto& encoded : methods) {
                if (encoded.code_off == 0U) continue;
                const auto& method = source.methods().at(encoded.method_idx);
                const auto method_key = owner + "->" +
                    source.string(method.name_idx) + source.proto_key(method.proto_idx);
                const auto code = dex::DecodeCodeItem(source, encoded.code_off);
                std::set<std::uint32_t> leaders{0U};
                for (const auto& instruction : code.instructions) {
                    leaders.insert(instruction.targets.begin(), instruction.targets.end());
                    if (instruction.kind == dex::InstructionKind::ConditionalBranch ||
                        instruction.kind == dex::InstructionKind::Switch) {
                        leaders.insert(instruction.offset + instruction.width);
                    }
                }
                std::map<std::uint16_t,
                         std::pair<std::uint32_t, std::string>> live_strings;
                for (const auto& instruction : code.instructions) {
                    if (leaders.contains(instruction.offset) &&
                        instruction.offset != 0U) {
                        live_strings.clear();
                    }
                    if (instruction.opcode == 0x1aU || instruction.opcode == 0x1bU) {
                        const auto index = instruction.opcode == 0x1aU ?
                            static_cast<std::uint32_t>(instruction.code_units.at(1U)) :
                            static_cast<std::uint32_t>(instruction.code_units.at(1U)) |
                                static_cast<std::uint32_t>(
                                    instruction.code_units.at(2U)) << 16U;
                        const auto destination = static_cast<std::uint16_t>(
                            instruction.code_units.front() >> 8U);
                        live_strings.insert_or_assign(
                            destination,
                            std::pair{instruction.offset, source.string(index)});
                        continue;
                    }
                    if (const auto argument = ReflectionArgumentFor(source, instruction);
                        argument.has_value()) {
                        const auto registers = InvokeRegisters(instruction);
                        if (argument->register_ordinal < registers.size()) {
                            const auto live = live_strings.find(
                                registers[argument->register_ordinal]);
                            if (live != live_strings.end()) {
                                if (const auto replacement = ReflectionReplacement(
                                        live->second.second, argument->kind, plan);
                                    replacement.has_value()) {
                                    result.insert_or_assign(
                                        method_key + ':' +
                                            std::to_string(live->second.first),
                                        ReflectionSiteReplacement{
                                            argument->kind,
                                            live->second.second,
                                            *replacement});
                                }
                            }
                        }
                    }
                    if (const auto destination = DestinationRegister(instruction);
                        destination.has_value()) {
                        live_strings.erase(*destination);
                        if (instruction.opcode == 0x04U || instruction.opcode == 0x05U ||
                            instruction.opcode == 0x06U || instruction.opcode == 0x0bU ||
                            instruction.opcode == 0x10U || instruction.opcode == 0x13U ||
                            instruction.opcode == 0x14U || instruction.opcode == 0x15U ||
                            instruction.opcode == 0x16U || instruction.opcode == 0x17U ||
                            instruction.opcode == 0x18U || instruction.opcode == 0x19U) {
                            live_strings.erase(static_cast<std::uint16_t>(*destination + 1U));
                        }
                    }
                    if (instruction.kind != dex::InstructionKind::Normal) {
                        live_strings.clear();
                    }
                }
            }
        };
        collect(data.direct_methods);
        collect(data.virtual_methods);
    }
    return result;
}


void ModelReflectionProtection::ApplyReflectionSiteMap(std::vector<dex::ClassSpec>& classes,
                            const ReflectionSiteMap& replacements) {
    for (auto& klass : classes) {
        for (auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
            for (auto& method : *methods) {
                auto method_key = klass.descriptor + "->" + method.name + "(";
                for (const auto& parameter : method.parameter_types) {
                    method_key += parameter;
                }
                method_key += ")" + method.return_type;
                for (auto& patch : method.body.references) {
                    auto* value = std::get_if<std::string>(&patch.reference);
                    if (value == nullptr || patch.code_unit == 0U) continue;
                    const auto found = replacements.find(
                        method_key + ':' + std::to_string(patch.code_unit - 1U));
                    if (found != replacements.end()) {
                        *value = found->second.target;
                    }
                }
            }
        }
    }
}


void ModelReflectionProtection::IndirectReflectionTargets(
    dex::ClassSpec& klass, const GuardConfig& config,
    ModelLoweringResult& report,
    std::vector<dex::ClassSpec>& generated_classes,
    std::set<std::string, std::less<>>& used_descriptors) {
    const auto& pass = config.passes.at("reflection.indirect_targets");
    if (!pass.enabled) return;
    dex::ClassSpec proxy;
    proxy.descriptor = SyntheticClassDescriptor(
        "reflection-proxy", klass.descriptor, config.seed,
        generated_classes.size(), used_descriptors);
    proxy.access_flags = 0x1011U; // public final synthetic
    std::set<std::string, std::less<>> used_names;
    std::map<std::string, dex::MethodReference, std::less<>> proxies;
    std::size_t ordinal = 0U;
    for (auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (auto& method : *methods) {
            const auto method_key = klass.descriptor + "->" + method.name;
            std::uint32_t applications = 0U;
            for (auto& patch : method.body.references) {
                auto* target = std::get_if<dex::MethodReference>(
                    &patch.reference);
                if (target == nullptr || !IsIndirectReflectionTarget(*target) ||
                    patch.code_unit == 0U ||
                    (pass.max_applications_per_method.has_value() &&
                     applications >= *pass.max_applications_per_method)) {
                    continue;
                }
                const auto invoke_at = patch.code_unit - 1U;
                if (invoke_at >= method.body.code_units.size()) continue;
                const auto opcode = static_cast<std::uint8_t>(
                    method.body.code_units[invoke_at]);
                const auto base_opcode = InvokeBaseOpcode(opcode);
                if (base_opcode != 0x6eU && base_opcode != 0x71U &&
                    base_opcode != 0x72U) {
                    continue;
                }
                const auto site = method_key + ':' + std::to_string(invoke_at);
                if (!Selected(pass, config.seed, site, 0x494e4452U)) continue;
                const auto identity = MethodIdentity(*target) + ':' +
                    std::to_string(base_opcode);
                auto found = proxies.find(identity);
                if (found == proxies.end()) {
                    auto name = ReflectionProxyName(config.seed, ordinal++,
                                                    used_names);
                    used_names.insert(name);
                    auto generated = BuildReflectionProxyMethod(
                        name, *target, base_opcode);
                    const dex::MethodReference proxy_reference{
                        proxy.descriptor, generated.name,
                        generated.return_type, generated.parameter_types};
                    proxy.direct_methods.push_back(std::move(generated));
                    found = proxies.emplace(identity, proxy_reference).first;
                }
                patch.reference = found->second;
                method.body.code_units[invoke_at] =
                    static_cast<std::uint16_t>(
                        (method.body.code_units[invoke_at] & 0xff00U) |
                        (opcode >= 0x74U ? 0x77U : 0x71U));
                ++applications;
                ++report.pass_applications["reflection.indirect_targets"];
            }
        }
    }
    if (!proxy.direct_methods.empty()) {
        used_descriptors.insert(proxy.descriptor);
        generated_classes.push_back(std::move(proxy));
    }
}


} // namespace birch::guard::detail
