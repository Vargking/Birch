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

#include "model_classes.h"
#include "model_methods.h"
#include "model_arrays.h"
#include "model_enums.h"
#include "model_runtime.h"
#include "model_strings.h"
#include "model_reflection.h"
#include "model_metadata.h"
#include "model_support.h"
#include "static_field_initializer.h"
#include "class_namespace.h"

namespace birch::guard {
using namespace detail;
namespace {

constexpr std::array<std::string_view, 23U> kModelPasses{
    "rename.parameters",
    "cfg.tail_recursion", "structure.method_outlining",
    "structure.method_splitting", "structure.method_inlining",
    "structure.proxy_stubs", "structure.class_splitting",
    "structure.class_merging", "structure.interface_abstract_conversion",
    "anti_analysis.annotation_noise", "anti_analysis.annotation_forgery",
    "anti_analysis.debug_local_noise", "data.string_encryption",
    "data.string_splitting", "data.reflection_string_encryption",
    "data.array_virtualization", "data.array_splitting",
    "data.enum_lowering", "loading.encrypted_paths",
    "reflection.indirect_targets", "data.constant_splitting",
    "data.boolean_arithmetic", "anti_analysis.constant_barriers",
};


} // namespace

bool DexModelLowering::HasPasses(const GuardConfig& config) {
    return ModelRuntimeBuilder::HasRuntimeOpaquePasses(config) ||
        ModelRuntimeBuilder::HasRuntimeExceptionPasses(config) ||
        std::any_of(kModelPasses.begin(), kModelPasses.end(), [&](const auto id) {
        const auto found = config.passes.find(std::string(id));
        if (found == config.passes.end()) {
            throw std::invalid_argument("missing pass configuration: " +
                                        std::string(id));
        }
        return found->second.enabled;
    });
}

bool DexModelLowering::HasReflectionRenameSites(
    const dex::DexFile& source, const ReflectionRenamePlan& plan) {
    return !ModelReflectionProtection::BuildReflectionSiteMap(source, plan).empty();
}

ReflectionRenamePlan DexModelLowering::UsedReflectionRenames(
    const dex::DexFile& source, const ReflectionRenamePlan& plan) {
    ReflectionRenamePlan result;
    for (const auto& [site, replacement] :
         ModelReflectionProtection::BuildReflectionSiteMap(source, plan)) {
        (void)site;
        if (replacement.kind == ReflectionStringKind::Method) {
            result.methods.insert_or_assign(replacement.source,
                                            replacement.target);
            continue;
        }
        if (replacement.kind == ReflectionStringKind::Field) {
            result.fields.insert_or_assign(replacement.source,
                                           replacement.target);
            continue;
        }
        auto source_descriptor = replacement.source;
        if (!plan.classes.contains(source_descriptor)) {
            source_descriptor = "L" + source_descriptor + ";";
            std::replace(source_descriptor.begin(), source_descriptor.end(),
                         '.', '/');
        }
        const auto found = plan.classes.find(source_descriptor);
        if (found == plan.classes.end()) {
            throw std::logic_error(
                "reflection class replacement lost its rename source");
        }
        result.classes.insert_or_assign(source_descriptor, found->second);
    }
    return result;
}

ModelLoweringResult DexModelLowering::Apply(
    const dex::DexFile& source,
    const std::set<std::string, std::less<>>& reserved_descriptors) const {
    ModelLoweringResult result;
    for (const auto id : kModelPasses) {
        result.pass_applications.try_emplace(std::string(id), 0U);
    }
    const ScopeMatcher scope(config_->scope);
    dex::DexClassCloner cloner(source);
    std::vector<dex::ClassSpec> classes;
    classes.reserve(source.classes().size());
    for (std::size_t class_index = 0U; class_index < source.classes().size();
         ++class_index) {
        classes.push_back(cloner.Clone(class_index));
    }
    if (reflection_renames_ != nullptr) {
        ModelReflectionProtection::ApplyReflectionSiteMap(
            classes, ModelReflectionProtection::BuildReflectionSiteMap(source, *reflection_renames_));
    }
    ModelClassStructure::MergeStaticUtilityClasses(classes, *config_, result);
    ModelClassStructure::ConvertInterfaceAbstractClasses(classes, *config_, result);

    dex::DexBuilder builder(source.version());
    ClassNamespace class_namespace(reserved_descriptors);
    class_namespace.Reserve(source);
    auto descriptors = class_namespace.names();
    std::vector<dex::ClassSpec> generated_classes;
    std::vector<ArrayAccessorPlan> array_plans;
    std::vector<EnumLoweringPlan> enum_plans;
    StringRewritePlan string_plan;
    const auto descriptor_seed = ModelRuntimeBuilder::SourceShardSeed(classes, config_->seed);
    for (const auto& klass : classes) descriptors.insert(klass.descriptor);
    for (auto& klass : classes) {
        if (scope.IsProtected(klass.descriptor) &&
            scope.AllowsCodeTransforms(klass.descriptor)) {
            // Inline trivial private/static bodies before class splitting.
            // Otherwise class splitting can move the candidate into a
            // companion class that is outside this class-local inline pass.
            ModelMethodStructure::InlineTrivialMethods(klass, *config_, result);
            // Reflection sites must be redirected before class splitting moves
            // their bodies into generated companions. Generated proxy bodies
            // are intentionally not scanned again, so their terminal platform
            // calls remain the only direct reflection edges.
            ModelReflectionProtection::IndirectReflectionTargets(klass, *config_, result,
                                      generated_classes, descriptors);
            // Tail-recursive loop lowering also has to inspect the original
            // loop body. Class splitting would otherwise move it to a
            // companion outside this class-local structural pass.
            if (config_->passes.at("structure.class_splitting").enabled) {
                ModelMethodStructure::ApplyTailRecursionBeforeClassSplit(klass, *config_, result);
            }
            // Class splitting must still see the original non-trivial bodies;
            // running it after the wrapper passes makes every wrapper appear
            // to depend on a private same-owner helper.
            ModelClassStructure::SplitStaticMethods(klass, *config_, result, generated_classes,
                               descriptors);
            ModelMethodStructure::TransformClass(klass, *config_, result, generated_classes,
                           descriptors);
            ModelArrayProtection::AddArrayAccessors(klass, *config_, array_plans);
            ModelEnumProtection::AddEnumProtocol(klass, *config_, enum_plans);
            ModelStringProtection::CollectStringValues(klass, *config_, string_plan);
        }
    }
    for (auto& generated : generated_classes) {
        ModelStringProtection::CollectStringValues(generated, *config_, string_plan);
    }
    if (ModelRuntimeBuilder::HasRuntimeOpaquePasses(*config_)) {
        for (auto& helper : ModelRuntimeBuilder::BuildOpaqueHelpers(
                 descriptors, descriptor_seed, config_->seed, *config_)) {
            descriptors.insert(helper.descriptor);
            builder.AddClass(std::move(helper));
        }
    }
    if (ModelRuntimeBuilder::HasRuntimeExceptionPasses(*config_)) {
        auto helper = ModelRuntimeBuilder::BuildExceptionFlowHelper(
            descriptors, descriptor_seed, config_->seed, *config_);
        descriptors.insert(helper.descriptor);
        builder.AddClass(std::move(helper));
    }
    if (ModelRuntimeBuilder::HasRuntimeConstantPasses(*config_)) {
        auto helper = ModelRuntimeBuilder::BuildConstantBarrierHelper(
            descriptors, descriptor_seed, config_->seed);
        descriptors.insert(helper.descriptor);
        builder.AddClass(std::move(helper));
    }
    const auto string_passes_enabled =
        config_->passes.at("data.string_encryption").enabled ||
        config_->passes.at("data.string_splitting").enabled ||
        config_->passes.at("data.reflection_string_encryption").enabled ||
        config_->passes.at("loading.encrypted_paths").enabled ||
        config_->passes.at("reflection.indirect_targets").enabled;
    std::string string_helper_descriptor;
    std::vector<dex::ClassSpec> string_helpers;
    if (string_passes_enabled && !string_plan.values.empty()) {
        auto helpers = ModelStringProtection::BuildStringHelper(
            descriptors, string_plan.values, string_plan.split_values,
            descriptor_seed, config_->seed);
        string_helper_descriptor = helpers.entry_descriptor;
        string_helpers = std::move(helpers.classes);
        for (const auto& helper : string_helpers) {
            descriptors.insert(helper.descriptor);
        }
    }
    StaticFieldInitializer::Rewrite(classes, *config_, string_helper_descriptor,
                                    string_plan, result);
    StaticFieldInitializer::Rewrite(generated_classes, *config_, string_helper_descriptor,
                                    string_plan, result, true);
    for (auto& klass : classes) {
        builder.AddClass(std::move(klass));
    }
    for (auto& generated : generated_classes) {
        builder.AddClass(std::move(generated));
    }
    for (auto& helper : string_helpers) {
        builder.AddClass(std::move(helper));
    }
    result.bytes = builder.Build();
    // Consume the string plan before other data rewrites. Stable const-string
    // ordinals survive builder jumbo promotions; array/enum passes rediscover
    // their own sites from symbolic fields/methods after the vault rewrite.
    if (!string_helper_descriptor.empty()) {
        auto transformed = dex::DexFile::Parse(result.bytes);
        std::size_t rewritten = 0U;
        const auto rewritten_bytes = ModelStringProtection::RewriteStringCallsites(
            transformed, string_plan, string_helper_descriptor, config_->seed,
            rewritten, result);
        if (rewritten != 0U) {
            transformed = dex::DexFile::Parse(rewritten_bytes);
            result.bytes = CompactDex(transformed);
            result.encrypted_strings = rewritten;
        }
    }
    if (!array_plans.empty()) {
        auto transformed = dex::DexFile::Parse(result.bytes);
        std::size_t rewritten = 0U;
        const auto rewritten_bytes = ModelArrayProtection::RewriteArrayCallsites(
            transformed, array_plans, rewritten, result);
        if (rewritten != 0U) {
            result.bytes = rewritten_bytes;
        }
    }
    if (!enum_plans.empty()) {
        const auto transformed = dex::DexFile::Parse(result.bytes);
        result.bytes = ModelEnumProtection::RewriteEnumCallsites(transformed, enum_plans, result);
    }
    dex::VerifyDexOrThrow(dex::DexFile::Parse(result.bytes),
                          dex::VerificationLevel::Full);
    return result;
}

} // namespace birch::guard
