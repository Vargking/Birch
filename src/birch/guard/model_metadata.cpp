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

#include "model_metadata.h"
#include "model_support.h"

namespace birch::guard::detail {
namespace {

dex::AnnotationSpec NoiseAnnotation(std::uint64_t seed, std::size_t ordinal,
                                    bool forged) {
    dex::EncodedAnnotationSpec annotation;
    const auto type_seed = utils::StableHash64(
        forged ? "annotation-forgery-type" : "annotation-noise-type",
        seed ^ ordinal);
    const auto package_seed = utils::StableHash64(
        "annotation-package", seed ^ (ordinal << 1U));
    std::ostringstream type_stream;
    type_stream << 'L' << 'a' << std::hex << std::setfill('0') << std::setw(8)
                << static_cast<std::uint32_t>(package_seed) << "/a"
                << std::setw(8) << static_cast<std::uint32_t>(type_seed) << ';';
    annotation.type = type_stream.str();
    annotation.elements.push_back({
        forged ? "origin" : "token",
        dex::EncodedValueSpec{dex::StringReference{
            std::to_string(utils::StableHash64(
                annotation.type + std::to_string(ordinal), seed))}}});
    annotation.elements.push_back({
        "revision", dex::EncodedValueSpec{
            static_cast<std::int32_t>(seed ^ ordinal)}});
    auto shape = std::make_shared<dex::EncodedArraySpec>();
    const auto shape_seed = utils::StableHash64(
        annotation.type + ":shape", seed ^ (ordinal << 3U));
    for (std::size_t index = 0U; index < 8U; ++index) {
        shape->values.emplace_back(dex::EncodedValueSpec{
            static_cast<std::int32_t>(utils::StableHash64(
                std::to_string(index), shape_seed))});
    }
    annotation.elements.push_back({"shape", dex::EncodedValueSpec{shape}});
    auto nested = std::make_shared<dex::EncodedAnnotationSpec>();
    nested->type = forged ? "La/marker/F;" : "La/marker/N;";
    nested->elements.push_back({
        "salt", dex::EncodedValueSpec{static_cast<std::int32_t>(
            utils::StableHash64("nested", shape_seed))}});
    nested->elements.push_back({
        "ordinal", dex::EncodedValueSpec{static_cast<std::int32_t>(ordinal)}});
    annotation.elements.push_back({"route", dex::EncodedValueSpec{nested}});
    return {forged ? std::uint8_t{1U} : std::uint8_t{0U},
            std::move(annotation)};
}


} // namespace

void ModelMetadata::AddMetadataNoise(dex::ClassSpec& klass, const GuardConfig& config,
                      ModelLoweringResult& report) {
    const auto& annotation_noise = config.passes.at("anti_analysis.annotation_noise");
    const auto& annotation_forgery = config.passes.at("anti_analysis.annotation_forgery");
    const auto& debug_noise = config.passes.at("anti_analysis.debug_local_noise");
    const auto add_annotations = [&](auto& annotations, std::string_view key,
                                     std::size_t ordinal) {
        const auto noise_selected = Selected(annotation_noise, config.seed, key,
                                             0x414e4e4fU);
        const auto forgery_selected = Selected(annotation_forgery, config.seed,
                                               key, 0x464f5247U);
        const auto noise_count = noise_selected ?
            2U + static_cast<std::size_t>(std::ceil(annotation_noise.intensity * 2.0)) :
            0U;
        const auto forgery_count = forgery_selected ?
            2U + static_cast<std::size_t>(std::ceil(annotation_forgery.intensity * 2.0)) :
            0U;
        for (std::size_t index = 0U; index < noise_count; ++index) {
            annotations.push_back(NoiseAnnotation(
                config.seed, ordinal * 8U + index, false));
            ++report.annotation_noise_items;
            ++report.pass_applications["anti_analysis.annotation_noise"];
        }
        for (std::size_t index = 0U; index < forgery_count; ++index) {
            annotations.push_back(NoiseAnnotation(
                config.seed, ordinal * 8U + noise_count + index, true));
            ++report.annotation_noise_items;
            ++report.pass_applications["anti_analysis.annotation_forgery"];
        }
    };
    std::size_t ordinal = 0U;
    add_annotations(klass.annotations, klass.descriptor, ordinal++);
    for (auto* fields : {&klass.static_fields, &klass.instance_fields}) {
        for (auto& field : *fields) {
            add_annotations(field.annotations,
                klass.descriptor + "->" + field.name, ordinal++);
        }
    }
    for (auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (auto& method : *methods) {
            const auto key = klass.descriptor + "->" + method.name;
            add_annotations(method.annotations, key, ordinal++);
            if (!debug_noise.enabled || !method.body.debug_info.has_value() ||
                method.body.registers_size == 0U ||
                !Selected(debug_noise, config.seed, key, 0x44454247U)) {
                continue;
            }
            const auto cycles = 2U + static_cast<std::size_t>(
                std::ceil(debug_noise.intensity * 6.0));
            for (std::size_t cycle = 0U; cycle < cycles; ++cycle) {
                const auto reg = static_cast<std::uint32_t>(
                    cycle % method.body.registers_size);
                const auto token = utils::StableHash64(
                    key + ":debug:" + std::to_string(cycle),
                    debug_noise.seed.value_or(config.seed));
                dex::DebugEventSpec start;
                start.kind = (cycle & 1U) == 0U ?
                    dex::DebugEventKind::StartLocal :
                    dex::DebugEventKind::StartLocalExtended;
                start.register_index = reg;
                start.name = "v" + std::to_string(token);
                start.type = "I";
                if (start.kind == dex::DebugEventKind::StartLocalExtended) {
                    start.signature = "T" + std::to_string(token >> 17U) + ";";
                }
                method.body.debug_info->events.push_back(std::move(start));
                dex::DebugEventSpec end;
                end.kind = dex::DebugEventKind::EndLocal;
                end.register_index = reg;
                method.body.debug_info->events.push_back(std::move(end));
            }
            ++report.debug_noise_methods;
            ++report.pass_applications["anti_analysis.debug_local_noise"];
        }
    }
}


void ModelMetadata::RenameDebugParameters(dex::ClassSpec& klass, const GuardConfig& config,
                           ModelLoweringResult& report) {
    const auto& pass = config.passes.at("rename.parameters");
    if (!pass.enabled) return;
    std::size_t ordinal = 0U;
    for (auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (auto& method : *methods) {
            if (!method.body.debug_info.has_value() ||
                !Selected(pass, config.seed, klass.descriptor + "->" + method.name,
                          0x50415241U)) {
                continue;
            }
            auto& names = method.body.debug_info->parameter_names;
            for (auto& name : names) {
                if (!name.has_value()) continue;
                *name = "$p" + std::to_string(utils::StableHash64(
                    klass.descriptor + "->" + method.name + ":" +
                    std::to_string(ordinal++),
                    pass.seed.value_or(config.seed)) & 0xffffffffU);
                ++report.pass_applications["rename.parameters"];
            }
        }
    }
}


} // namespace birch::guard::detail
