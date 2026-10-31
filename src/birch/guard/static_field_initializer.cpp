#include "static_field_initializer.h"

#include "model_support.h"
#include "birch/guard/scope.h"
#include "birch/guard/string_runtime.h"
#include "birch/utils/hash.h"

#include <algorithm>
#include <bit>
#include <iterator>
#include <stdexcept>
#include <type_traits>

namespace birch::guard::detail {
namespace {

std::optional<std::uint32_t> ScalarBits(const dex::FieldSpec& field) {
    if (!field.static_value) return std::nullopt;
    return std::visit([&](const auto& value) -> std::optional<std::uint32_t> {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, float>) {
            if (field.type == "F") return std::bit_cast<std::uint32_t>(value);
        } else if constexpr (std::is_same_v<T, bool> || std::is_same_v<T, std::int8_t> ||
                             std::is_same_v<T, std::int16_t> || std::is_same_v<T, char16_t> ||
                             std::is_same_v<T, std::int32_t>) {
            if (field.type == "Z" || field.type == "B" || field.type == "C" ||
                field.type == "S" || field.type == "I")
                return static_cast<std::uint32_t>(value);
        }
        return std::nullopt;
    }, field.static_value->value);
}

std::uint8_t StaticPutOpcode(std::string_view type) {
    if (type == "Z") return 0x6aU;
    if (type == "B") return 0x6bU;
    if (type == "C") return 0x6cU;
    if (type == "S") return 0x6dU;
    if (type == "I" || type == "F") return 0x67U;
    if (!type.empty() && (type.front() == 'L' || type.front() == '[')) return 0x69U;
    throw std::logic_error("unsupported generated static field store type");
}

void ShiftOriginalBody(dex::MethodBodySpec& body, std::uint32_t shift) {
    for (auto& patch : body.references) patch.code_unit += shift;
    if (body.invoke_reference) body.invoke_reference_unit += shift;
    for (auto& patch : body.invoke_references) patch.code_unit += shift;
    for (auto& patch : body.string_references) patch.code_unit += shift;
    for (auto& region : body.try_regions) {
        region.start_address += shift;
        for (auto& handler : region.handlers) handler.address += shift;
    }
    body.debug_info.reset();
}

void RewriteClass(dex::ClassSpec& klass, const GuardConfig& config,
                  std::string_view helper, const StringRewritePlan& strings,
                  ModelLoweringResult& report) {
    dex::MethodBodySpec prefix;
    // Reserve room for full-strength CFF, typed dispatch and 1024 dead states.
    // Split only at complete field initializations, never across a live v0.
    // Constant materialization runs before CFF and can expand each of the
    // three masked constants again. Budget for that phase, not just this IR.
    constexpr std::size_t kChunkCodeUnits = 256U;
    std::vector<dex::MethodBodySpec> chunks;
    const bool encrypt_strings = config.passes.at("data.string_encryption").enabled ||
                                 config.passes.at("data.string_splitting").enabled;
    const bool split_constants = config.passes.at("data.constant_splitting").enabled;
    std::vector<dex::FieldSpec*> rewritten;
    for (auto& field : klass.static_fields) {
        if (!field.static_value) continue;
        const auto* text = std::get_if<dex::StringReference>(&field.static_value->value);
        const auto bits = split_constants ? ScalarBits(field) : std::nullopt;
        if (text && encrypt_strings && strings.values.contains(text->value)) {
            if (helper.empty()) throw std::logic_error("static string vault is missing");
            AppendInvoke35c(prefix.code_units, 0x71U, {}, prefix,
                {std::string(helper), RuntimeStringMethodName(text->value, config.seed),
                 "Ljava/lang/String;", {}});
            prefix.code_units.push_back(0x000cU);
            ++report.pass_applications[config.passes.at("data.string_encryption").enabled ?
                                       "data.string_encryption" : "data.string_splitting"];
        } else if (bits) {
            const auto state = utils::StableHash64(klass.descriptor + "->" + field.name,
                                                   config.seed ^ 0x4649454c44ULL);
            const auto key_a = static_cast<std::uint16_t>(state | 1U);
            const auto key_b = static_cast<std::uint16_t>((state >> 23U) | 1U);
            const auto signed_key = [](std::uint16_t key) {
                return static_cast<std::uint32_t>(static_cast<std::int32_t>(
                    std::bit_cast<std::int16_t>(key)));
            };
            const auto initial = *bits ^ signed_key(key_a) ^ signed_key(key_b);
            prefix.code_units.insert(prefix.code_units.end(), {
                0x0014U, static_cast<std::uint16_t>(initial),
                static_cast<std::uint16_t>(initial >> 16U),
                0x00d7U, key_b, 0x00d7U, key_a});
            if (field.type == "F") {
                // Numeric int-to-float (or int-to-long) destroys IEEE-754 bits.
                // Use the raw-bit identity to produce an explicitly typed F.
                AppendInvoke35c(prefix.code_units, 0x71U, {0U}, prefix,
                    {"Ljava/lang/Float;", "intBitsToFloat", "F", {"I"}});
                prefix.code_units.push_back(0x000aU);
                prefix.outs_size = 1U;
            }
            ++report.pass_applications["data.constant_splitting"];
        } else {
            continue;
        }
        prefix.code_units.push_back(StaticPutOpcode(field.type));
        prefix.code_units.push_back(0U);
        prefix.references.push_back({dex::FieldReference{klass.descriptor, field.name, field.type},
            static_cast<std::uint32_t>(prefix.code_units.size() - 1U), false});
        rewritten.push_back(&field);
        if (prefix.code_units.size() >= kChunkCodeUnits) {
            chunks.push_back(std::move(prefix));
            prefix = {};
        }
    }
    if (chunks.empty() && prefix.code_units.empty()) return;
    if (!chunks.empty()) {
        if (!prefix.code_units.empty()) chunks.push_back(std::move(prefix));
        prefix = {};
        std::set<std::string, std::less<>> used;
        for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods})
            for (const auto& method : *methods) used.insert(method.name);
        const auto seed = utils::StableHash64(klass.descriptor, config.seed);
        for (std::size_t i = 0; i < chunks.size(); ++i) {
            dex::MethodSpec method;
            method.name = SyntheticName(seed, "static-initializer", i, used);
            used.insert(method.name);
            method.access_flags = kPrivate | kStatic | kSynthetic;
            method.body = std::move(chunks[i]);
            method.body.registers_size = 1U;
            method.body.code_units.push_back(0x000eU);
            // Same declaring class is essential for private/final field access.
            // Helpers are created before code lowering, so none bypass CFF.
            AppendInvoke35c(prefix.code_units, 0x71U, {}, prefix,
                MethodReferenceFor(klass, method));
            klass.direct_methods.push_back(std::move(method));
        }
    }
    // All original relative branch/payload offsets remain valid only if their
    // instructions move together. Preserve payloads' even code-unit alignment.
    if ((prefix.code_units.size() & 1U) != 0U) prefix.code_units.push_back(0x0000U);
    auto clinit = std::find_if(klass.direct_methods.begin(), klass.direct_methods.end(),
        [](const auto& method) { return method.name == "<clinit>"; });
    if (clinit == klass.direct_methods.end()) {
        dex::MethodSpec method;
        method.name = "<clinit>";
        method.access_flags = 0x10008U; // ACC_STATIC | ACC_CONSTRUCTOR
        method.body.code_units = {0x000eU};
        klass.direct_methods.push_back(std::move(method));
        clinit = std::prev(klass.direct_methods.end());
    }
    if (clinit->body.ins_size != 0U || !clinit->parameter_types.empty() ||
        clinit->return_type != "V" || (clinit->access_flags & kStatic) == 0U)
        throw std::runtime_error("invalid static initializer ABI for " + klass.descriptor);
    auto& body = clinit->body;
    // clinit has no arguments: v0 is undefined at entry, so there is nothing
    // to spill or restore. Reusing it works even at the v255 register budget.
    const auto shift = static_cast<std::uint32_t>(prefix.code_units.size());
    ShiftOriginalBody(body, shift);
    body.code_units.insert(body.code_units.begin(), prefix.code_units.begin(), prefix.code_units.end());
    body.references.insert(body.references.end(),
        std::make_move_iterator(prefix.references.begin()), std::make_move_iterator(prefix.references.end()));
    body.registers_size = std::max<std::uint16_t>(body.registers_size, 1U);
    body.outs_size = std::max(body.outs_size, prefix.outs_size);
    for (auto* field : rewritten) field->static_value.reset();
}

} // namespace

void StaticFieldInitializer::Rewrite(std::vector<dex::ClassSpec>& classes,
                                     const GuardConfig& config,
                                     std::string_view string_helper_descriptor,
                                     const StringRewritePlan& strings,
                                     ModelLoweringResult& report,
                                     bool generated_classes) {
    const ScopeMatcher scope(config.scope);
    for (auto& klass : classes) {
        if (!generated_classes && (!scope.IsProtected(klass.descriptor) ||
                                    !scope.AllowsCodeTransforms(klass.descriptor))) continue;
        RewriteClass(klass, config, string_helper_descriptor, strings, report);
    }
}

} // namespace birch::guard::detail
