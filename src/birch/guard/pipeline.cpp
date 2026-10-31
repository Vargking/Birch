#include "birch/guard/pipeline.h"
#include "technique_report.h"

#include "rename_names.h"
#include "rename_planner.h"
#include "output_linkage.h"
#include "output_code_budget.h"
#include "apk_dex_layout.h"
#include "class_namespace.h"
#include "resource_obfuscator.h"

#include "birch/dex/program.h"
#include "birch/dex/cloner.h"
#include "birch/dex/checksum.h"
#include "birch/dex/code.h"
#include "birch/dex/ir.h"
#include "birch/dex/cfg.h"
#include "birch/dex/verifier.h"
#include "birch/dex/remap.h"
#include "birch/guard/arsc.h"
#include "birch/guard/axml.h"
#include "birch/guard/dex_lowering.h"
#include "birch/guard/fake.h"
#include "birch/guard/model_lowering.h"
#include "birch/guard/opaque_runtime.h"
#include "birch/guard/scope.h"
#include "birch/io/apk_entries.h"
#include "birch/io/file.h"
#include "birch/io/path.h"
#include "birch/utils/hash.h"
#include "birch/utils/wildcard.h"

#include <algorithm>
#include <stdexcept>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <span>
#include <array>
#include <sstream>
#include <optional>

namespace birch::guard {
using detail::NameGenerator;
using detail::RenamePlanner;
using detail::GlobalRenamePlan;
namespace {

std::vector<std::uint8_t> RewriteClassList(
    std::span<const std::uint8_t> bytes,
    const std::map<std::string, std::string, std::less<>>& replacements) {
    const std::string input(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    std::string output;
    output.reserve(input.size());
    std::size_t cursor = 0U;
    while (cursor < input.size()) {
        const auto newline = input.find('\n', cursor);
        const auto line_end = newline == std::string::npos ? input.size() : newline;
        auto content_end = line_end;
        const auto has_cr = content_end > cursor && input[content_end - 1U] == '\r';
        if (has_cr) --content_end;
        auto begin = cursor;
        while (begin < content_end && (input[begin] == ' ' || input[begin] == '\t')) ++begin;
        auto end = content_end;
        while (end > begin && (input[end - 1U] == ' ' || input[end - 1U] == '\t')) --end;
        output.append(input, cursor, begin - cursor);
        const auto value = input.substr(begin, end - begin);
        const auto found = replacements.find(value);
        if (found != replacements.end()) {
            output += found->second;
        } else {
            // Some Xposed/service lists use a package prefix (for example
            // `com.example`) instead of a concrete class.  Apply the longest
            // dotted-prefix mapping while preserving comments and whitespace.
            std::string replacement(value);
            std::size_t best = 0U;
            for (const auto& [old_name, new_name] : replacements) {
                if (old_name.size() <= best || value.size() <= old_name.size() ||
                    value.compare(0U, old_name.size(), old_name) != 0 ||
                    value[old_name.size()] != '.') {
                    continue;
                }
                if (old_name.size() > best) {
                    best = old_name.size();
                    replacement = new_name + value.substr(old_name.size());
                }
            }
            output += replacement;
        }
        output.append(input, end, content_end - end);
        if (has_cr) output.push_back('\r');
        if (newline != std::string::npos) output.push_back('\n');
        cursor = newline == std::string::npos ? input.size() : newline + 1U;
    }
    return {output.begin(), output.end()};
}

bool IsClassListEntry(std::string_view name) {
    return name == "META-INF/xposed/java_init.list" ||
           name == "META-INF/xposed/init.list" ||
           name == "META-INF/xposed/scope.list" ||
           name == "assets/xposed_init" ||
           name == "assets/xposed_init.list" ||
           name.starts_with("META-INF/services/");
}

std::map<std::string, std::string, std::less<>> ManifestRelativeAliases(
    const std::map<std::string, std::string, std::less<>>& class_map) {
    std::map<std::string, std::string, std::less<>> result;
    std::set<std::string, std::less<>> ambiguous;
    const auto add = [&](std::string source, const std::string& target) {
        if (ambiguous.contains(source)) return;
        const auto found = result.find(source);
        if (found == result.end()) {
            result.emplace(std::move(source), target);
        } else if (found->second != target) {
            ambiguous.insert(source);
            result.erase(found);
        }
    };
    for (const auto& [old_descriptor, new_descriptor] : class_map) {
        if (old_descriptor.size() < 3U || new_descriptor.size() < 3U) continue;
        auto old_dotted = old_descriptor.substr(1U, old_descriptor.size() - 2U);
        auto new_dotted = new_descriptor.substr(1U, new_descriptor.size() - 2U);
        std::replace(old_dotted.begin(), old_dotted.end(), '/', '.');
        std::replace(new_dotted.begin(), new_dotted.end(), '/', '.');
        for (auto dot = old_dotted.find('.'); dot != std::string::npos;
             dot = old_dotted.find('.', dot + 1U)) {
            add(old_dotted.substr(dot), new_dotted);
        }
        const auto last = old_dotted.rfind('.');
        if (last != std::string::npos && last + 1U < old_dotted.size()) {
            add(old_dotted.substr(last + 1U), new_dotted);
        }
    }
    return result;
}

void WriteMappingFile(const GuardConfig& config,
                      const std::vector<std::string>& mapping_lines,
                      const std::vector<std::string>& warnings) {
    if (!config.output.write_mapping || config.output.mapping_file.empty()) return;
    std::ostringstream mapping;
    mapping << "# BirchGuard seed=" << config.seed << '\n';
    for (const auto& warning : warnings) mapping << "# WARNING " << warning << '\n';
    for (const auto& line : mapping_lines) mapping << line << '\n';
    io::WriteTextFile(io::Utf8Path(config.output.mapping_file), mapping.str());
}

std::optional<dex::DexFile> LoadFrameworkDex(const GuardConfig& config) {
    if (config.android_dex.empty()) return std::nullopt;
    try {
        return dex::DexFile::Parse(io::ReadBinaryFile(io::Utf8Path(config.android_dex)));
    } catch (const std::exception& error) {
        throw std::runtime_error("cannot load android_dex '" +
                                 config.android_dex + "': " + error.what());
    }
}

bool IsLoweredDexPass(std::string_view id) {
    const auto runtime_opaque = std::find(
        kRuntimeOpaquePasses.begin(), kRuntimeOpaquePasses.end(), id) !=
        kRuntimeOpaquePasses.end();
    return runtime_opaque || id == "rename.parameters" ||
           id == "rename.classes" || id == "rename.methods" ||
           id == "rename.fields" || id == "rename.packages" ||
           id == "rename.overload_induction" ||
           id == "structure.package_flattening" ||
           id == "structure.method_splitting" ||
           id == "structure.method_outlining" ||
           id == "structure.method_inlining" ||
           id == "structure.class_splitting" ||
           id == "structure.class_merging" ||
           id == "structure.interface_abstract_conversion" ||
           id == "structure.proxy_stubs" ||
           id == "reflection.indirect_targets" ||
           id == "loading.encrypted_paths" ||
           id == "cfg.flattening" || id == "cfg.nested_flattening" ||
           id == "cfg.multi_state_dispatch" || id == "cfg.bogus_edges" ||
           id == "cfg.loop_state_machine" || id == "cfg.table_dispatch" ||
           id == "cfg.indirect_dispatch" || id == "cfg.mixed_ps_ss_if" ||
           id == "cfg.dead_blocks" ||
           id == "cfg.condition_expansion" || id == "cfg.conditional_nesting" ||
           id == "cfg.exception_dispatch" || id == "cfg.callback_style" ||
           id == "cfg.block_reordering" || id == "cfg.tail_recursion" ||
           id == "anti_analysis.pattern_randomization" ||
           id == "anti_analysis.dataflow_pollution" ||
           id == "anti_analysis.path_explosion" ||
           id == "anti_analysis.ssa_pollution" ||
           id == "anti_analysis.instruction_patterns" ||
           id == "anti_analysis.register_shape" ||
           id == "anti_analysis.legal_exception_layout" ||
           id == "anti_analysis.verifier_safe_overlap_substitute" ||
           id == "anti_analysis.decompiler_resilience" ||
           id == "anti_analysis.legal_overlapping_handlers" ||
           id == "anti_analysis.constant_barriers" ||
           id == "anti_analysis.annotation_noise" ||
           id == "anti_analysis.annotation_forgery" ||
           id == "anti_analysis.debug_local_noise" ||
           id == "anti_analysis.debug_info_removal" ||
           id == "data.constant_splitting" ||
           id == "data.boolean_arithmetic" ||
           id == "data.string_encryption" ||
           id == "data.string_splitting" ||
           id == "data.reflection_string_encryption" ||
           id == "data.array_virtualization" ||
           id == "data.array_splitting" ||
           id == "data.enum_lowering" ||
           id.starts_with("strength.");
}

bool RuntimeOpaqueEnabled(const GuardConfig& config) {
    return std::any_of(kRuntimeOpaquePasses.begin(),
                       kRuntimeOpaquePasses.end(), [&](const auto id) {
        return config.passes.at(std::string(id)).enabled;
    });
}

bool FakeEnabled(const GuardConfig& config) {
    return config.passes.at("fake.classes").enabled ||
           config.passes.at("fake.calls").enabled;
}

void ProtectGeneratedFakeScope(GuardConfig& config) {
    if (!FakeEnabled(config)) return;
    auto pattern = config.fake.package_prefix + "**;";
    const auto already_present = std::any_of(
        config.scope.protect.begin(), config.scope.protect.end(),
        [&](const auto& rule) { return rule.pattern == pattern; });
    if (!already_present) {
        config.scope.protect.push_back({std::move(pattern), true, true, true});
    }
}

bool ClassRenameEnabled(const GuardConfig& config) {
    return FakeEnabled(config) || config.passes.at("rename.classes").enabled ||
           config.passes.at("rename.packages").enabled ||
           config.passes.at("structure.package_flattening").enabled;
}

bool MethodRenameEnabled(const GuardConfig& config) {
    return FakeEnabled(config) || config.passes.at("rename.methods").enabled ||
           config.passes.at("rename.overload_induction").enabled;
}

std::vector<dex::MethodBodySpec::MethodReference> CollectFakeRealTargets(
    const ZipArchive& archive, const ScopeConfig& scope,
    const std::map<std::string, std::string, std::less<>>& class_map) {
    std::set<std::string, std::less<>> renamed_protected;
    for (const auto& [old_name, new_name] : class_map) {
        (void)old_name;
        renamed_protected.insert(new_name);
    }
    std::set<std::string, std::less<>> seen;
    std::vector<dex::MethodBodySpec::MethodReference> result;
    for (const auto& entry : archive.entries()) {
        if (!io::IsDexEntryName(entry.name)) continue;
        const auto dex_file = dex::DexFile::Parse(entry.data);
        for (std::size_t class_index = 0U; class_index < dex_file.classes().size(); ++class_index) {
            const auto owner = dex_file.descriptor(dex_file.classes()[class_index].class_idx);
            const auto protected_owner = !renamed_protected.empty() ?
                renamed_protected.contains(owner) :
                (!MatchesAnyScopeRule(owner, scope.keep) && MatchesAnyScopeRule(owner, scope.protect));
            if (!protected_owner) continue;
            for (const auto& encoded : dex_file.class_data(class_index).direct_methods) {
                constexpr std::uint32_t kPublicStatic = 0x0001U | 0x0008U;
                if ((encoded.access_flags & kPublicStatic) != kPublicStatic ||
                    encoded.code_off == 0U) continue;
                const auto& method = dex_file.methods().at(encoded.method_idx);
                const auto name = dex_file.string(method.name_idx);
                if (NameGenerator::IsSpecialMethod(name)) continue;
                const auto& proto = dex_file.protos().at(method.proto_idx);
                std::vector<std::string> parameters;
                std::uint32_t parameter_words = 0U;
                for (const auto type_idx : dex_file.type_list(proto.parameters_off)) {
                    auto descriptor = dex_file.descriptor(type_idx);
                    parameter_words += descriptor == "J" || descriptor == "D" ? 2U : 1U;
                    parameters.push_back(std::move(descriptor));
                }
                if (parameter_words > 5U) continue;
                const auto return_type = dex_file.descriptor(proto.return_type_idx);
                const auto key = owner + "->" + name + dex_file.proto_key(method.proto_idx);
                if (!seen.insert(key).second) continue;
                result.push_back({owner, name, return_type, std::move(parameters)});
                if (result.size() >= 256U) return result;
            }
        }
    }
    return result;
}

ScopeConfig PipelineScope(const GuardConfig& config) {
    auto scope = config.scope;
    if (config.passes.at("fake.classes").enabled ||
        config.passes.at("fake.calls").enabled) {
        scope.protect.push_back({config.fake.package_prefix + "**;", true,
                                 true, true});
    }
    return scope;
}

std::set<std::string, std::less<>> ClassDescriptorSet(
    const dex::DexFile& dex_file) {
    std::set<std::string, std::less<>> result;
    for (const auto& definition : dex_file.classes()) {
        result.insert(dex_file.descriptor(definition.class_idx));
    }
    return result;
}

std::uint64_t DexBytes(const ZipArchive& archive) {
    std::uint64_t result = 0U;
    for (const auto& entry : archive.entries()) {
        if (!io::IsDexEntryName(entry.name)) continue;
        if (entry.data.size() >
            std::numeric_limits<std::uint64_t>::max() - result) {
            throw std::length_error("aggregate DEX size exceeds uint64");
        }
        result += entry.data.size();
    }
    return result;
}

std::string CodePassApplicationSummary(
    const GuardConfig& config,
    const std::map<std::string, std::size_t, std::less<>>& applications) {
    std::ostringstream stream;
    bool first = true;
    for (const auto& [id, count] : applications) {
        const auto configured = config.passes.find(id);
        if (configured == config.passes.end() || !configured->second.enabled) {
            continue;
        }
        if (!first) stream << ", ";
        first = false;
        stream << id << '=' << count;
    }
    return stream.str();
}

void VerifyDebugMetadataRemoved(const dex::DexFile& file,
                                std::string_view entry_name) {
    const auto debug_map = std::find_if(
        file.map().begin(), file.map().end(),
        [](const dex::DexMapItem& item) { return item.type == 0x2003U; });
    if (debug_map != file.map().end()) {
        throw std::runtime_error(
            "debug_info map entry survived stripping in " +
            std::string(entry_name));
    }
    for (std::size_t class_index = 0U;
         class_index < file.classes().size(); ++class_index) {
        if (file.classes()[class_index].source_file_idx != 0xffffffffU) {
            throw std::runtime_error(
                "source_file_idx survived debug stripping in " +
                std::string(entry_name));
        }
        const auto& data = file.class_data(class_index);
        for (const auto* methods : {&data.direct_methods,
                                    &data.virtual_methods}) {
            for (const auto& method : *methods) {
                if (method.code_off == 0U) continue;
                if (dex::DecodeCodeItem(file, method.code_off).debug_info_off !=
                    0U) {
                    throw std::runtime_error(
                        "debug_info_off survived stripping in " +
                        std::string(entry_name));
                }
            }
        }
    }
}

void EnforceDexGrowthBudget(std::uint64_t input_size,
                            std::uint64_t output_size,
                            double max_ratio,
                            std::string_view context) {
    const auto limit = static_cast<long double>(input_size) *
                       static_cast<long double>(max_ratio);
    if (static_cast<long double>(output_size) > limit) {
        throw std::runtime_error(
            std::string(context) + " exceeds max_dex_growth_ratio: input=" +
            std::to_string(input_size) + ", output=" +
            std::to_string(output_size) + ", ratio=" +
            std::to_string(max_ratio));
    }
}

std::size_t ProtectNewClassDescriptors(
    GuardConfig& config,
    const std::set<std::string, std::less<>>& before,
    const dex::DexFile& after) {
    std::size_t added = 0U;
    for (const auto& definition : after.classes()) {
        const auto descriptor = after.descriptor(definition.class_idx);
        if (before.contains(descriptor) ||
            MatchesAnyScopeRule(descriptor, config.scope.keep) ||
            MatchesAnyScopeRule(descriptor, config.scope.protect)) {
            continue;
        }
        config.scope.protect.push_back({descriptor, true, true, true});
        ++added;
    }
    return added;
}

} // namespace

GuardPipeline GuardPipeline::FromJson(std::string_view config_json) {
    return FromConfig(GuardConfig::Parse(config_json));
}

GuardPipeline GuardPipeline::FromConfig(GuardConfig config) {
    config.Validate();
    return GuardPipeline(std::move(config));
}

GuardReport GuardPipeline::InspectApk(const std::filesystem::path& apk) const {
    return InspectApk(apk, {});
}

GuardReport GuardPipeline::InspectApk(const std::filesystem::path& apk, ProgressSink sink) const {
    const auto emit = [&](ProgressStage stage, std::size_t current, std::size_t total,
                          std::string message, std::string pass = {}) {
        if (!sink) return;
        sink({stage, std::move(pass), apk.string(), current, total,
              total == 0U ? 0.0 : static_cast<double>(current) / static_cast<double>(total),
              std::move(message)});
    };
    emit(ProgressStage::Load, 0U, 1U, "reading APK");
    const auto archive = ZipArchive::Read(apk);
    emit(ProgressStage::Parse, 0U, archive.entries().size(), "validating APK entries");
    GuardReport report;
    report.inspection = guard::InspectApk(archive);
    emit(ProgressStage::Parse, archive.entries().size(), archive.entries().size(), "APK entries validated");
    for (const auto& pass : config_.passes) {
        if (pass.second.enabled) report.enabled_passes.push_back(pass.first);
    }
    std::vector<dex::DexInput> inputs;
    for (const auto& entry : archive.entries()) {
        if (io::IsDexEntryName(entry.name)) {
            inputs.push_back({entry.name, entry.data});
        }
    }
    const auto program = dex::DexProgram::Parse(std::move(inputs));
    const auto classes = program.classes();
    emit(ProgressStage::Scope, 0U, classes.size(), "matching protect/keep scope");
    for (std::size_t index = 0; index < classes.size(); ++index) {
        const auto handle = classes[index];
        const auto descriptor = program.class_descriptor(handle);
        if (MatchesAnyScopeRule(descriptor, config_.scope.keep)) ++report.kept_classes;
        else if (MatchesAnyScopeRule(descriptor, config_.scope.protect)) ++report.protected_classes;
        if ((index + 1U) % 256U == 0U || index + 1U == classes.size()) {
            emit(ProgressStage::Scope, index + 1U, classes.size(), "scope matched");
        }
    }
    emit(ProgressStage::Complete, 1U, 1U, "inspection complete");
    return report;
}

void GuardPipeline::TransformDex(const std::filesystem::path& input,
                                 const std::filesystem::path& output) const {
    TransformDex(input, output, {});
}

void GuardPipeline::TransformDex(const std::filesystem::path& input,
                                 const std::filesystem::path& output,
                                 ProgressSink sink) const {
    detail::TechniqueReport::ValidatePaths(config_, input, output);
    detail::TechniqueReport technique_report;
    auto config = config_;
    config.seed = StrengthRandomizedSeed(config);
    config.scope = PipelineScope(config);
    const auto emit = [&](ProgressStage stage, std::string message,
                          std::string pass = {}) {
        if (sink) sink({stage, std::move(pass), input.string(), 0U, 0U, 0.0,
                        std::move(message)});
    };
    emit(ProgressStage::Load, "reading DEX");
    auto bytes = io::ReadBinaryFile(input);
    const auto input_dex_size = static_cast<std::uint64_t>(bytes.size());
    auto dex_file = dex::DexFile::Parse(bytes);
    emit(ProgressStage::Parse, "DEX parsed");

    // Debug programs must be removed before any code/model rewrite. Some
    // toolchains emit debug PCs that point into a multi-code-unit instruction;
    // those streams are irrelevant when removal is requested and cannot be
    // relocated safely by later writers.
    if (config.passes.at("anti_analysis.debug_info_removal").enabled) {
        bytes = dex_file.StripDebugInfo();
        dex_file = dex::DexFile::Parse(bytes);
        emit(ProgressStage::Transform, "stripped DEX debug info before lowering",
             "anti_analysis.debug_info_removal");
    }

    for (const auto& [id, pass] : config.passes) {
        if (pass.enabled && !IsLoweredDexPass(id)) {
            emit(ProgressStage::Error, "requested DEX transform is not yet lowered by writer", id);
            throw std::runtime_error("requested DEX transform is not yet lowered by writer: " + id);
        }
    }
    if (config.resources.rename_files || config.resources.rename_names ||
        config.signing.enabled) {
        throw std::runtime_error("APK resource/signing options are invalid for DEX output");
    }
    emit(ProgressStage::Plan, "building enabled DEX pass plan");

    const auto rename_enabled = ClassRenameEnabled(config) ||
                                MethodRenameEnabled(config) ||
                                config.passes.at("rename.fields").enabled;
    std::optional<GlobalRenamePlan> pre_model_rename_plan;
    std::optional<GlobalRenamePlan> reflection_rename_locks;
    std::optional<ReflectionRenamePlan> reflection_rename_plan;
    if (rename_enabled) {
        const std::vector<std::reference_wrapper<const dex::DexFile>> one_dex{
            dex_file};
        const auto framework_dex = LoadFrameworkDex(config);
        pre_model_rename_plan = RenamePlanner::BuildGlobalRenamePlan(
            one_dex, config.scope, config.rename, config.seed,
            ClassRenameEnabled(config), MethodRenameEnabled(config),
            config.passes.at("rename.fields").enabled,
            config.passes.at("rename.overload_induction").enabled,
            config.passes.at("rename.overload_induction").intensity,
            framework_dex.has_value() ? &*framework_dex : nullptr);
        const auto candidates = RenamePlanner::BuildReflectionRenamePlan(
            *pre_model_rename_plan);
        auto used = DexModelLowering::UsedReflectionRenames(
            dex_file, candidates);
        if (!RenamePlanner::EmptyReflectionRenamePlan(used)) {
            reflection_rename_locks = RenamePlanner::BuildReflectionRenameLocks(used);
            reflection_rename_plan = std::move(used);
        }
    }

    const auto* reflection_plan = reflection_rename_plan.has_value() &&
            DexModelLowering::HasReflectionRenameSites(
                dex_file, *reflection_rename_plan) ?
        &*reflection_rename_plan : nullptr;
    if (DexModelLowering::HasPasses(config) || reflection_plan != nullptr) {
        const auto before_descriptors = ClassDescriptorSet(dex_file);
        const auto model = DexModelLowering(config, reflection_plan).Apply(dex_file);
        technique_report.Add(model.pass_applications);
        bytes = model.bytes;
        dex_file = dex::DexFile::Parse(bytes);
        const auto protected_generated =
            ProtectNewClassDescriptors(config, before_descriptors, dex_file);
        emit(ProgressStage::Transform,
             "model-lowered " + std::to_string(model.outlined_methods) +
             " outlined, " + std::to_string(model.split_methods) +
             " split method(s) in " + std::to_string(model.split_classes) +
             " companion class(es), " +
             std::to_string(model.proxy_methods) +
             " proxied, " + std::to_string(model.inlined_calls) +
             " inlined, " + std::to_string(model.merged_classes) +
             " merged class(es), " + std::to_string(model.converted_classes) +
             " interface/abstract conversion(s), " +
             std::to_string(model.virtualized_arrays) + " virtualized array(s), " +
             std::to_string(model.split_arrays) + " split array(s), " +
             std::to_string(model.lowered_enums) + " lowered enum(s), " +
             std::to_string(model.annotation_noise_items) +
             " metadata-noise item(s), " +
             std::to_string(model.debug_noise_methods) + " debug-noise and " +
             std::to_string(model.tail_recursive_methods) +
             " tail-recursive method(s), " +
             std::to_string(model.encrypted_strings) +
             " encrypted string callsite(s), protected " +
             std::to_string(protected_generated) +
              " generated runtime class(es)");
        const auto model_pass_summary = CodePassApplicationSummary(
            config, model.pass_applications);
        if (!model_pass_summary.empty()) {
            emit(ProgressStage::Transform,
                 "model-pass applications: " + model_pass_summary);
        }
    }

    const auto lowered = DexCodeLowering(config).Apply(dex_file);
    technique_report.Add(lowered.pass_applications);
    bytes = lowered.bytes;
    dex_file = dex::DexFile::Parse(bytes);
    if (lowered.debug_removed) {
        emit(ProgressStage::Transform, "stripped DEX debug info",
             "anti_analysis.debug_info_removal");
    }
    if (DexCodeLowering::HasControlFlowPasses(config)) {
        emit(ProgressStage::Transform,
             "lowered " + std::to_string(lowered.cfg_methods) +
             " method CFG(s), including " +
             std::to_string(lowered.flattened_methods) +
             " complete dispatcher flattening(s)");
    }
    if (lowered.constants_rewritten != 0U) {
        emit(ProgressStage::Transform,
             "rewrote " + std::to_string(lowered.constants_rewritten) +
             " constant(s) across " + std::to_string(lowered.data_methods) +
             " method(s)", "data.constant_splitting");
    }
    if (RuntimeOpaqueEnabled(config) && lowered.cfg_methods != 0U) {
        emit(ProgressStage::Transform,
             "injected runtime opaque-state calls into " +
             std::to_string(lowered.cfg_methods) + " method(s)",
             "predicate.runtime_state");
    }

    std::vector<std::string> mapping_lines;
    std::vector<std::string> warnings;
    dex::LinkageRenames linkage_renames;
    if (rename_enabled) {
        const std::vector<std::reference_wrapper<const dex::DexFile>> one_dex{dex_file};
        const auto framework_dex = LoadFrameworkDex(config);
        const auto rename_plan = RenamePlanner::BuildGlobalRenamePlan(
            one_dex, config.scope, config.rename, config.seed,
            ClassRenameEnabled(config), MethodRenameEnabled(config),
            config.passes.at("rename.fields").enabled,
            config.passes.at("rename.overload_induction").enabled,
            config.passes.at("rename.overload_induction").intensity,
            framework_dex.has_value() ? &*framework_dex : nullptr,
            reflection_rename_locks.has_value() ?
                &*reflection_rename_locks : nullptr);
        linkage_renames = {rename_plan.classes, rename_plan.methods, rename_plan.fields};
        if (reflection_rename_locks.has_value()) {
            RenamePlanner::ValidateStablePreModelRenamePlan(*reflection_rename_locks,
                                             rename_plan);
        }
        auto renamed = RenamePlanner::RenameDex(dex_file, config.scope, config.rename, config.seed,
                                 ClassRenameEnabled(config), MethodRenameEnabled(config),
                                 config.passes.at("rename.fields").enabled,
                                 &rename_plan);
        bytes = std::move(renamed.bytes);
        mapping_lines = std::move(renamed.mapping_lines);
        warnings = rename_plan.warnings;
        warnings.insert(warnings.end(), renamed.warnings.begin(), renamed.warnings.end());
        dex_file = dex::DexFile::Parse(bytes);
        emit(ProgressStage::Transform, "renamed DEX identifiers");
    }

    EnforceDexGrowthBudget(
        input_dex_size, bytes.size(), config.budget.max_dex_growth_ratio,
        "DEX output");
    dex::VerifyDexOrThrow(dex_file, dex::VerificationLevel::Full);
    detail::OutputCodeBudget::Verify(dex_file, config, linkage_renames.classes);
    const auto linkage_framework = LoadFrameworkDex(config);
    detail::OutputLinkage::VerifyDex(input, dex_file,
        linkage_framework.has_value() ? &*linkage_framework : nullptr, linkage_renames);
    emit(ProgressStage::Verify, "DEX program linkage verification passed");
    emit(ProgressStage::Verify, "DEX full verification passed");
    io::WriteBinaryFile(output, bytes);
    WriteMappingFile(config, mapping_lines, warnings);
    technique_report.Write(config, output, warnings, false);
    emit(ProgressStage::Write, "DEX written");
    emit(ProgressStage::Complete, "DEX transform complete");
}

void GuardPipeline::TransformApk(const std::filesystem::path& input,
                                 const std::filesystem::path& output) const {
    TransformApk(input, output, {});
}

void GuardPipeline::TransformApk(const std::filesystem::path& input,
                                 const std::filesystem::path& output,
                                 ProgressSink sink) const {
    detail::TechniqueReport::ValidatePaths(config_, input, output);
    detail::TechniqueReport technique_report;
    auto config = config_;
    config.seed = StrengthRandomizedSeed(config);
    ProtectGeneratedFakeScope(config);
    config.scope = PipelineScope(config);
    const auto emit = [&](ProgressStage stage, std::string message) {
        if (sink) sink({stage, {}, input.string(), 0U, 0U, 0.0, std::move(message)});
    };
    emit(ProgressStage::Load, "effective protection seed=" + std::to_string(config.seed));
    emit(ProgressStage::Load, "reading APK");
    (void)InspectApk(input, sink);
    emit(ProgressStage::Plan, "building enabled pass plan");
    // Resource transforms can be selected either through the legacy resource
    // options or through their first-class pass ids.  Keep both forms
    // equivalent so a pass-only configuration is not silently ignored.
    for (const auto& pass : config.passes) {
        if (pass.second.enabled && pass.first != "resources.file_rename" && pass.first != "resources.name_rename" &&
            !IsLoweredDexPass(pass.first) &&
            pass.first != "fake.classes" &&
            pass.first != "fake.calls" &&
            pass.first.rfind("strength.", 0U) != 0U) {
            emit(ProgressStage::Error, "requested DEX transform is not yet lowered by writer");
            throw std::runtime_error("requested DEX transform is not yet lowered by writer: " + pass.first);
        }
    }
    auto archive = ZipArchive::Read(input);
    const auto resource_plan = detail::ResourceObfuscator::Plan(archive, config);
    const detail::ApkDexLayout dex_layout(archive);
    const auto input_dex_size = DexBytes(archive);
    if (config.passes.at("anti_analysis.debug_info_removal").enabled) {
        for (const auto& name : io::DexEntryNames(archive)) {
            auto* entry = archive.FindMutable(name);
            if (entry == nullptr) {
                throw std::runtime_error(
                    "DEX disappeared during early debug stripping: " + name);
            }
            const auto parsed = dex::DexFile::Parse(entry->data);
            entry->data = parsed.StripDebugInfo();
        }
        emit(ProgressStage::Transform,
             "stripped DEX debug info before model and rename planning");
    }
    detail::ClassNamespace class_namespace;
    for (const auto& name : io::DexEntryNames(archive)) {
        class_namespace.Reserve(dex::DexFile::Parse(archive.Find(name)->data));
    }
    for (const auto& info : archive.entries()) {
        auto* aligned = archive.FindMutable(info.name);
        if (aligned == nullptr ||
            aligned->compression != ZipCompression::Stored) continue;
        const auto native_library = info.name.starts_with("lib/") &&
                                    info.name.ends_with(".so");
        aligned->alignment = native_library ? 16384U : 4U;
    }
    std::optional<GlobalRenamePlan> pre_model_rename_plan;
    std::optional<GlobalRenamePlan> reflection_rename_locks;
    std::optional<ReflectionRenamePlan> reflection_rename_plan;
    const auto rename_enabled = ClassRenameEnabled(config) ||
                                MethodRenameEnabled(config) ||
                                config.passes.at("rename.fields").enabled;
    if (rename_enabled) {
        const auto dex_names = io::DexEntryNames(archive);
        std::vector<dex::DexFile> planning_dex_files;
        planning_dex_files.reserve(dex_names.size());
        for (const auto& name : dex_names) {
            const auto* entry = archive.Find(name);
            if (entry == nullptr) {
                throw std::runtime_error(
                    "DEX disappeared during reflection rename planning: " + name);
            }
            planning_dex_files.push_back(dex::DexFile::Parse(entry->data));
        }
        std::vector<std::reference_wrapper<const dex::DexFile>> references;
        references.reserve(planning_dex_files.size());
        for (const auto& dex_file : planning_dex_files) {
            references.emplace_back(dex_file);
        }
        const auto framework_dex = LoadFrameworkDex(config);
        pre_model_rename_plan = RenamePlanner::BuildGlobalRenamePlan(
            references, config.scope, config.rename, config.seed,
            ClassRenameEnabled(config), MethodRenameEnabled(config),
            config.passes.at("rename.fields").enabled,
            config.passes.at("rename.overload_induction").enabled,
            config.passes.at("rename.overload_induction").intensity,
            framework_dex.has_value() ? &*framework_dex : nullptr);
        const auto candidates = RenamePlanner::BuildReflectionRenamePlan(
            *pre_model_rename_plan);
        ReflectionRenamePlan used;
        for (const auto& dex_file : planning_dex_files) {
            RenamePlanner::MergeReflectionRenamePlan(
                used, DexModelLowering::UsedReflectionRenames(
                          dex_file, candidates));
        }
        if (!RenamePlanner::EmptyReflectionRenamePlan(used)) {
            reflection_rename_locks = RenamePlanner::BuildReflectionRenameLocks(used);
            reflection_rename_plan = std::move(used);
        }
        emit(ProgressStage::Plan,
             "planned reflection-aware pre-model rename closure");
    }
    if (DexModelLowering::HasPasses(config) ||
        reflection_rename_plan.has_value()) {
        for (const auto& name : io::DexEntryNames(archive)) {
            auto* entry = archive.FindMutable(name);
            if (entry == nullptr) {
                throw std::runtime_error(
                    "DEX disappeared during model lowering: " + name);
            }
            const auto before_dex = dex::DexFile::Parse(entry->data);
            const auto* reflection_plan = reflection_rename_plan.has_value() &&
                    DexModelLowering::HasReflectionRenameSites(
                        before_dex, *reflection_rename_plan) ?
                &*reflection_rename_plan : nullptr;
            if (!DexModelLowering::HasPasses(config) &&
                reflection_plan == nullptr) {
                continue;
            }
            const auto before_descriptors = ClassDescriptorSet(before_dex);
            const auto model = DexModelLowering(
                config, reflection_plan).Apply(before_dex, class_namespace.names());
            entry->data = model.bytes;
            technique_report.Add(model.pass_applications);
            const auto after_dex = dex::DexFile::Parse(entry->data);
            class_namespace.Reserve(after_dex);
            const auto protected_generated =
                ProtectNewClassDescriptors(config, before_descriptors,
                                           after_dex);
            emit(ProgressStage::Transform,
                 "model-lowered " + name + ": " +
                 std::to_string(model.outlined_methods) + " outlined, " +
                 std::to_string(model.split_classes) + " split companion class(es), " +
                 std::to_string(model.split_methods) + " split, " +
                 std::to_string(model.proxy_methods) + " proxied, " +
                 std::to_string(model.inlined_calls) + " inlined, " +
                 std::to_string(model.merged_classes) + " merged class(es), " +
                 std::to_string(model.converted_classes) + " interface/abstract conversion(s), " +
                 std::to_string(model.virtualized_arrays) + " virtualized array(s), " +
                 std::to_string(model.split_arrays) + " split array(s), " +
                 std::to_string(model.lowered_enums) + " lowered enum(s), " +
                 std::to_string(model.annotation_noise_items) +
                 " metadata-noise, " +
                 std::to_string(model.debug_noise_methods) + " debug-noise, " +
                 std::to_string(model.tail_recursive_methods) +
                 " tail-recursive, " +
                 std::to_string(model.encrypted_strings) + " encrypted string callsite(s), " +
                 std::to_string(protected_generated) +
                 " generated runtime class(es) protected, " +
                  std::to_string(model.skipped_methods) + " skipped");
            const auto model_pass_summary = CodePassApplicationSummary(
                config, model.pass_applications);
            if (!model_pass_summary.empty()) {
                emit(ProgressStage::Transform,
                     "model-pass applications in " + name + ": " +
                     model_pass_summary);
            }
        }
    }

    // Fake classes must enter the archive before the global rename/code plan.
    // Appending them after rename leaves their descriptors, method
    // names, and call graph outside every subsequent lowering pass.
    if (FakeEnabled(config)) {
        FakeClassOptions fake_options;
        fake_options.package_prefix = config.fake.package_prefix;
        fake_options.class_count = config.fake.class_count;
        fake_options.methods_per_class = config.fake.methods_per_class;
        fake_options.seed = config.seed;
        fake_options.invoke_real_method = config.passes.at("fake.calls").enabled;
        fake_options.density = std::max(config.passes.at("fake.classes").intensity,
                                        config.passes.at("fake.calls").intensity);
        const auto existing_dex_names = io::DexEntryNames(archive);
        if (existing_dex_names.empty()) {
            throw std::runtime_error("cannot derive fake DEX version without a primary DEX");
        }
        const auto* primary_dex = archive.Find(existing_dex_names.front());
        if (primary_dex == nullptr) {
            throw std::runtime_error("primary DEX disappeared before fake injection");
        }
        fake_options.dex_version = dex::DexFile::Parse(primary_dex->data).version();
        if (fake_options.invoke_real_method) {
            fake_options.real_targets = CollectFakeRealTargets(archive, config.scope, {});
        }
        const auto fake_bytes = BuildFakeDex(fake_options);
        const auto fake_name = io::NextDexEntryName(archive);
        archive.Add({fake_name, fake_bytes, ZipCompression::Stored, 0U, 0U, 0U, 0U, 4U});
        emit(ProgressStage::Transform, "injected fake classes before global lowering into " + fake_name);
    }

    // Run model lowering on the freshly injected fake DEX as well. Existing
    // application DEX files were lowered above; the last DEX is the new one.
    if (DexModelLowering::HasPasses(config) && FakeEnabled(config)) {
        const auto names = io::DexEntryNames(archive);
        auto* entry = archive.FindMutable(names.back());
        if (entry == nullptr) throw std::runtime_error("injected fake DEX disappeared");
        const auto before_dex = dex::DexFile::Parse(entry->data);
        const auto* reflection_plan = reflection_rename_plan.has_value() &&
                DexModelLowering::HasReflectionRenameSites(
                    before_dex, *reflection_rename_plan) ?
            &*reflection_rename_plan : nullptr;
        const auto before_descriptors = ClassDescriptorSet(before_dex);
        class_namespace.Reserve(before_dex);
        const auto fake_model = DexModelLowering(
            config, reflection_plan).Apply(before_dex, class_namespace.names());
        entry->data = fake_model.bytes;
        technique_report.Add(fake_model.pass_applications);
        const auto after_dex = dex::DexFile::Parse(entry->data);
        const auto protected_generated =
            ProtectNewClassDescriptors(config, before_descriptors, after_dex);
        emit(ProgressStage::Transform,
             "model-lowered injected fake DEX: " +
             std::to_string(fake_model.outlined_methods) + " outlined, " +
             std::to_string(fake_model.split_classes) +
             " split companion class(es), " +
             std::to_string(fake_model.split_methods) + " split, " +
             std::to_string(fake_model.proxy_methods) + " proxied, " +
             std::to_string(fake_model.inlined_calls) + " inlined, " +
             std::to_string(fake_model.merged_classes) +
             " merged class(es), " +
             std::to_string(fake_model.converted_classes) +
             " interface/abstract conversion(s), " +
             std::to_string(fake_model.virtualized_arrays) +
             " virtualized array(s), " +
             std::to_string(fake_model.split_arrays) + " split array(s), " +
             std::to_string(fake_model.lowered_enums) + " lowered enum(s), " +
             std::to_string(fake_model.encrypted_strings) +
             " encrypted string callsite(s), " +
              std::to_string(fake_model.skipped_methods) + " skipped");
        const auto fake_model_pass_summary = CodePassApplicationSummary(
            config, fake_model.pass_applications);
        if (!fake_model_pass_summary.empty()) {
            emit(ProgressStage::Transform,
                 "model-pass applications in injected fake DEX: " +
                 fake_model_pass_summary);
        }
        if (protected_generated != 0U) {
            emit(ProgressStage::Transform,
                 "protected " + std::to_string(protected_generated) +
                 " generated runtime class(es) in injected fake DEX");
        }
    }
    std::map<std::string, std::string, std::less<>> global_class_map;
    dex::LinkageRenames linkage_renames;
    std::map<std::string, std::string, std::less<>> class_list_map;
    std::map<std::string, std::string, std::less<>> xml_map;
    std::vector<std::string> mapping_lines;
    std::vector<std::string> warnings;
    if (ClassRenameEnabled(config) || MethodRenameEnabled(config) ||
        config.passes.at("rename.fields").enabled) {
        const auto dex_names = io::DexEntryNames(archive);
        std::vector<dex::DexFile> planning_dex_files;
        planning_dex_files.reserve(dex_names.size());
        for (const auto& name : dex_names) {
            const auto* entry = archive.Find(name);
            if (entry == nullptr) throw std::runtime_error("DEX disappeared during rename planning: " + name);
            planning_dex_files.push_back(dex::DexFile::Parse(entry->data));
        }
        std::vector<std::reference_wrapper<const dex::DexFile>> planning_references;
        planning_references.reserve(planning_dex_files.size());
        for (const auto& dex_file : planning_dex_files) planning_references.emplace_back(dex_file);
        const auto framework_dex = LoadFrameworkDex(config);
        const auto rename_plan = RenamePlanner::BuildGlobalRenamePlan(
            planning_references, config.scope, config.rename, config.seed,
            ClassRenameEnabled(config), MethodRenameEnabled(config),
            config.passes.at("rename.fields").enabled,
            config.passes.at("rename.overload_induction").enabled,
            config.passes.at("rename.overload_induction").intensity,
            framework_dex.has_value() ? &*framework_dex : nullptr,
            reflection_rename_locks.has_value() ?
                &*reflection_rename_locks : nullptr);
        if (reflection_rename_locks.has_value()) {
            RenamePlanner::ValidateStablePreModelRenamePlan(*reflection_rename_locks,
                                             rename_plan);
        }
        global_class_map = rename_plan.classes;
        linkage_renames = {rename_plan.classes, rename_plan.methods, rename_plan.fields};
        warnings.insert(warnings.end(), rename_plan.warnings.begin(),
                        rename_plan.warnings.end());
        emit(ProgressStage::Plan,
             "planned global multi-DEX class/member rename closure");
        for (const auto& name : dex_names) {
            auto* entry = archive.FindMutable(name);
            if (entry == nullptr) throw std::runtime_error("DEX disappeared during rename: " + name);
            auto dex = dex::DexFile::Parse(entry->data);
            DexLoweringResult lowered;
            try {
                lowered = DexCodeLowering(config).Apply(dex);
            } catch (const std::exception& error) {
                throw std::runtime_error("code lowering failed for " + name + ": " +
                                         error.what());
            }
            entry->data = lowered.bytes;
            try {
                dex = dex::DexFile::Parse(entry->data);
            } catch (const std::exception& error) {
                throw std::runtime_error("rewritten DEX parse failed for " + name + ": " +
                                         error.what());
            }
            technique_report.Add(lowered.pass_applications);
            if (lowered.debug_removed) {
                emit(ProgressStage::Transform, "stripped debug info from " + name);
            }
            if (DexCodeLowering::HasControlFlowPasses(config)) {
                emit(ProgressStage::Transform,
                     "lowered " + std::to_string(lowered.cfg_methods) +
                     " method CFG(s), including " +
                     std::to_string(lowered.flattened_methods) +
                     " complete dispatcher flattening(s) in " + name);
            }
            if (lowered.constants_rewritten != 0U) {
                emit(ProgressStage::Transform,
                     "rewrote " +
                     std::to_string(lowered.constants_rewritten) +
                     " constant(s) in " + name);
            }
            if (RuntimeOpaqueEnabled(config) && lowered.cfg_methods != 0U) {
                emit(ProgressStage::Transform,
                     "injected runtime opaque-state calls into " +
                     std::to_string(lowered.cfg_methods) +
                     " method(s) in " + name);
            }
            const auto pass_summary = CodePassApplicationSummary(
                config, lowered.pass_applications);
            if (!pass_summary.empty()) {
                emit(ProgressStage::Transform,
                     "code-pass applications in " + name + ": " +
                     pass_summary);
            }
            const auto renamed = RenamePlanner::RenameDex(dex, config.scope, config.rename, config.seed,
                                           ClassRenameEnabled(config),
                                           MethodRenameEnabled(config),
                                           config.passes.at("rename.fields").enabled,
                                           &rename_plan);
            entry->data = renamed.bytes;
            global_class_map.insert(renamed.class_map.begin(), renamed.class_map.end());
            mapping_lines.insert(mapping_lines.end(), renamed.mapping_lines.begin(), renamed.mapping_lines.end());
            warnings.insert(warnings.end(), renamed.warnings.begin(), renamed.warnings.end());
            const auto rewritten = dex::DexFile::Parse(entry->data);
            if (!rewritten.VerifyChecksums()) {
                throw std::runtime_error("rewritten DEX failed checksum verification: " + name);
            }
            dex::VerifyDexOrThrow(rewritten, dex::VerificationLevel::Full);
            // Fail at the affected DEX rather than spending the remaining APK
            // transform on an already oversized post-rename code_item. The
            // final ZIP readback repeats this after merge/repartition.
            detail::OutputCodeBudget::Verify(rewritten, config, global_class_map);
            emit(ProgressStage::Transform, "renamed DEX " + name);
        }
        for (const auto& [old_descriptor, new_descriptor] : global_class_map) {
            xml_map.emplace(old_descriptor, new_descriptor);
            class_list_map.emplace(old_descriptor, new_descriptor);
            auto dotted_old = old_descriptor.substr(1U, old_descriptor.size() - 2U);
            auto dotted_new = new_descriptor.substr(1U, new_descriptor.size() - 2U);
            std::replace(dotted_old.begin(), dotted_old.end(), '/', '.');
            std::replace(dotted_new.begin(), dotted_new.end(), '/', '.');
            xml_map.emplace(dotted_old, dotted_new);
            class_list_map.emplace(dotted_old, dotted_new);
            const auto old_last = dotted_old.rfind('.');
            const auto new_last = dotted_new.rfind('.');
            if (old_last != std::string::npos && new_last != std::string::npos) {
                // Xposed scope/init lists may contain a package rather than a
                // concrete class.  Keep that entry in the same rename closure.
                class_list_map.emplace(dotted_old.substr(0U, old_last),
                                       dotted_new.substr(0U, new_last));
            }
        }
        for (const auto& entry : archive.entries()) {
            const auto class_list = IsClassListEntry(entry.name);
            const auto binary_xml = entry.name == "AndroidManifest.xml" ||
                                    (entry.name.starts_with("res/") && entry.name.ends_with(".xml"));
            if (!class_list && !binary_xml) continue;
            auto* mutable_entry = archive.FindMutable(entry.name);
            if (mutable_entry == nullptr) continue;
            if (class_list) {
                mutable_entry->data = RewriteClassList(mutable_entry->data,
                                                       class_list_map);
                continue;
            }
            if (mutable_entry->data.size() < 8U) continue;
            const auto type = static_cast<std::uint16_t>(mutable_entry->data[0]) | static_cast<std::uint16_t>(mutable_entry->data[1]) << 8U;
            if (type == 0x0003U) mutable_entry->data = AxmlDocument::Parse(mutable_entry->data).RenameStringsInPlace(xml_map);
        }
    }
    if ((config.passes.at("anti_analysis.debug_info_removal").enabled ||
         DexCodeLowering::HasInstructionPasses(config)) &&
        !(ClassRenameEnabled(config) || MethodRenameEnabled(config) ||
          config.passes.at("rename.fields").enabled)) {
        for (const auto& entry_info : archive.entries()) {
            if (!io::IsDexEntryName(entry_info.name)) continue;
            auto* entry = archive.FindMutable(entry_info.name);
            auto dex = dex::DexFile::Parse(entry->data);
            const auto lowered = DexCodeLowering(config).Apply(dex);
            technique_report.Add(lowered.pass_applications);
            entry->data = lowered.bytes;
            if (lowered.debug_removed) {
                emit(ProgressStage::Transform, "stripped debug info from " + entry_info.name);
            }
            if (DexCodeLowering::HasControlFlowPasses(config)) {
                emit(ProgressStage::Transform,
                     "lowered " + std::to_string(lowered.cfg_methods) +
                     " method CFG(s), including " +
                     std::to_string(lowered.flattened_methods) +
                     " complete dispatcher flattening(s) in " +
                     entry_info.name);
            }
            if (lowered.constants_rewritten != 0U) {
                emit(ProgressStage::Transform,
                     "rewrote " +
                     std::to_string(lowered.constants_rewritten) +
                     " constant(s) in " + entry_info.name);
            }
            const auto pass_summary = CodePassApplicationSummary(
                config, lowered.pass_applications);
            if (!pass_summary.empty()) {
                emit(ProgressStage::Transform,
                     "code-pass applications in " + entry_info.name + ": " +
                     pass_summary);
            }
            if (RuntimeOpaqueEnabled(config) && lowered.cfg_methods != 0U) {
                emit(ProgressStage::Transform,
                     "injected runtime opaque-state calls into " +
                     std::to_string(lowered.cfg_methods) +
                     " method(s) in " + entry_info.name);
            }
        }
    }
    // Each source DEX owns its independently generated runtime state. Lower
    // code and rename all units before cloning them into a shared final DEX.
    if (FakeEnabled(config)) {
        const auto generated_name = io::DexEntryNames(archive).back();
        if (dex_layout.MergeGeneratedDex(archive, generated_name, config.multidex.limits)) {
            emit(ProgressStage::Transform,
                 "merged all generated fake/runtime classes into primary DEX without reducing protection");
        }
    }
    if (config.multidex.repartition) {
        const auto dex_names = io::DexEntryNames(archive);
        std::vector<dex::DexInput> inputs;
        inputs.reserve(dex_names.size());
        for (const auto& name : dex_names) {
            const auto* entry = archive.Find(name);
            if (entry == nullptr) {
                throw std::runtime_error(
                    "DEX disappeared during repartition planning: " + name);
            }
            inputs.push_back({name, entry->data});
        }
        const auto program = dex::DexProgram::Parse(std::move(inputs));
        dex::RepartitionOptions repartition_options;
        repartition_options.partition.limits = config.multidex.limits;
        repartition_options.partition.preserve_input_order =
            config.multidex.preserve_input_order;
        std::map<std::string, std::string, std::less<>> current_to_original;
        for (const auto& [original, current] : global_class_map) {
            current_to_original.emplace(current, original);
        }
        const auto normalize_pattern = [](std::string pattern) {
            if (!pattern.empty() && pattern.front() == 'L') return pattern;
            std::replace(pattern.begin(), pattern.end(), '.', '/');
            if (!pattern.empty() && pattern.back() != ';' &&
                pattern.back() != '*') {
                pattern.push_back(';');
            }
            return 'L' + pattern;
        };
        std::vector<std::string> primary_patterns;
        primary_patterns.reserve(config.multidex.primary_dex_classes.size());
        for (const auto& pattern : config.multidex.primary_dex_classes) {
            primary_patterns.push_back(normalize_pattern(pattern));
        }
        for (const auto handle : program.classes()) {
            const auto current = program.class_descriptor(handle);
            const auto original = current_to_original.contains(current) ?
                current_to_original.at(current) : current;
            if (std::any_of(primary_patterns.begin(), primary_patterns.end(),
                    [&](const auto& pattern) {
                        return utils::WildcardMatch(original, pattern);
                    })) {
                repartition_options.partition.primary_dex_classes.insert(current);
            }
        }
        repartition_options.clone.preserve_debug_info = true;
        repartition_options.progress = [&](std::size_t current, std::size_t total,
                                           std::string_view phase) {
            if (sink) {
                sink({ProgressStage::Transform, "multidex.repartition",
                      input.string(), current, total,
                      total == 0U ? 0.0 :
                          static_cast<double>(current) /
                          static_cast<double>(total),
                      "DEX repartition " + std::string(phase) + " " +
                      std::to_string(current) + "/" +
                      std::to_string(total)});
            }
        };
        emit(ProgressStage::Transform,
             "repartitioning " + std::to_string(program.classes().size()) +
             " classes across DEX files");
        const auto repartitioned = dex::RepartitionProgram(
            program, repartition_options);
        for (const auto& name : dex_names) {
            if (!archive.RemoveEntry(name)) {
                throw std::runtime_error(
                    "failed to remove source DEX during repartition: " + name);
            }
        }
        const auto& limits = config.multidex.limits;
        for (std::size_t i = 0U; i < repartitioned.size(); ++i) {
            const auto& partition_output = repartitioned[i];
            const auto parsed = dex::DexFile::Parse(partition_output.bytes);
            if (parsed.strings().size() > limits.strings ||
                parsed.types().size() > limits.types ||
                parsed.protos().size() > limits.protos ||
                parsed.fields().size() > limits.fields ||
                parsed.methods().size() > limits.methods ||
                parsed.call_sites().size() > limits.call_sites ||
                parsed.method_handles().size() > limits.method_handles) {
                throw std::runtime_error(
                    "repartitioned DEX exceeds configured ID limit");
            }
            const auto name = i == 0U ? std::string("classes.dex") :
                "classes" + std::to_string(i + 1U) + ".dex";
            archive.Add({name, partition_output.bytes, ZipCompression::Stored,
                         0U, 0U, 0U, 0U, 4U});
        }
        emit(ProgressStage::Transform,
             "repartitioned DEX output into " +
             std::to_string(repartitioned.size()) + " file(s)");
    }
    resource_plan.Apply(archive);
    technique_report.Count("resources.file_rename", resource_plan.paths().size());
    technique_report.Count("resources.name_rename", resource_plan.names().size());
    mapping_lines.insert(mapping_lines.end(), resource_plan.mapping().begin(), resource_plan.mapping().end());
    warnings.insert(warnings.end(), resource_plan.warnings().begin(), resource_plan.warnings().end());
    // Key names are not generic XML strings. Only exact ARSC file paths join
    // the class-name closure; user-facing values/attributes remain untouched.
    if (!xml_map.empty() || !resource_plan.paths().empty()) {
        xml_map.insert(resource_plan.paths().begin(), resource_plan.paths().end());
        std::vector<std::string> entry_names;
        entry_names.reserve(archive.entries().size());
        for (const auto& entry : archive.entries()) entry_names.push_back(entry.name);
        const auto manifest_aliases = ManifestRelativeAliases(global_class_map);
        std::vector<std::pair<std::string, std::string>> service_entry_renames;
        for (const auto& name : entry_names) {
            const auto* entry = archive.Find(name);
            if (entry == nullptr) continue;
            const auto class_list = IsClassListEntry(name);
            const auto binary_xml = name == "AndroidManifest.xml" ||
                                    (name.starts_with("res/") && name.ends_with(".xml"));
            if (!class_list && !binary_xml) continue;
            auto* mutable_entry = archive.FindMutable(name);
            if (mutable_entry == nullptr) continue;
            if (class_list) {
                mutable_entry->data = RewriteClassList(mutable_entry->data,
                                                       class_list_map);
                constexpr std::string_view service_prefix = "META-INF/services/";
                if (name.starts_with(service_prefix)) {
                    const auto interface_name = name.substr(service_prefix.size());
                    const auto renamed = class_list_map.find(interface_name);
                    if (renamed != class_list_map.end() &&
                        renamed->second != interface_name) {
                        service_entry_renames.emplace_back(
                            name, std::string(service_prefix) + renamed->second);
                    }
                }
            } else if (mutable_entry->data.size() >= 8U) {
                const auto type = static_cast<std::uint16_t>(mutable_entry->data[0]) |
                                  static_cast<std::uint16_t>(mutable_entry->data[1]) << 8U;
                if (type == 0x0003U) {
                    const auto document = AxmlDocument::Parse(mutable_entry->data);
                    auto local_map = xml_map;
                    if (name == "AndroidManifest.xml") {
                        local_map.insert(manifest_aliases.begin(),
                                         manifest_aliases.end());
                    }
                    mutable_entry->data = document.RenameStringsInPlace(local_map);
                }
            }
        }
        for (const auto& [old_name, new_name] : service_entry_renames) {
            archive.RenameEntry(old_name, new_name);
        }
    }
    EnforceDexGrowthBudget(
        input_dex_size, DexBytes(archive),
        config.budget.max_dex_growth_ratio, "APK aggregate DEX output");
    if (!config.signing.enabled) {
        // The rewritten ZIP no longer matches any original v1/v2/v3 signature.
        std::vector<std::string> stale_signatures;
        for (const auto& entry : archive.entries()) {
            const auto leaf = entry.name.starts_with("META-INF/") ?
                std::string_view(entry.name).substr(9U) : std::string_view{};
            if (!leaf.empty() &&
                (leaf == "MANIFEST.MF" || leaf.starts_with("SIG-") ||
                 leaf.ends_with(".SF") || leaf.ends_with(".RSA") ||
                 leaf.ends_with(".DSA") || leaf.ends_with(".EC"))) {
                stale_signatures.push_back(entry.name);
            }
        }
        for (const auto& name : stale_signatures) (void)archive.RemoveEntry(name);
    } else {
        throw std::runtime_error("signing was requested but no APK signing backend is configured");
    }
    const auto bytes = archive.Write();
    const auto output_archive = ZipArchive::Read(bytes);
    (void)guard::InspectApk(output_archive);
    for (const auto& entry : output_archive.entries()) {
        if (io::IsDexEntryName(entry.name)) {
            if (entry.compression == ZipCompression::Stored && (entry.data_offset % 4U) != 0U) throw std::runtime_error("DEX ZIP data is not 4-byte aligned: " + entry.name);
            const auto dex = dex::DexFile::Parse(entry.data);
            const auto report = dex::VerifyDex(dex, dex::VerificationLevel::Full);
            if (!report.ok) {
                const auto message = report.issues.empty() ?
                    std::string("unspecified verifier failure") :
                    report.issues.front().message;
                throw std::runtime_error("final APK DEX verification failed: " +
                    entry.name + ": " + message);
            }
            if (config.passes.at("anti_analysis.debug_info_removal").enabled) {
                VerifyDebugMetadataRemoved(dex, entry.name);
            }
            detail::OutputCodeBudget::Verify(dex, config, global_class_map);
        }
    }
    const auto linkage_framework = LoadFrameworkDex(config);
    detail::OutputLinkage::VerifyApk(input, output_archive,
        linkage_framework.has_value() ? &*linkage_framework : nullptr, linkage_renames);
    emit(ProgressStage::Verify, "APK cross-DEX program linkage verification passed");
    dex_layout.Verify(output_archive, global_class_map);
    emit(ProgressStage::Verify, "APK legacy DEX loading layout verification passed");
    io::WriteBinaryFile(output, bytes);
    WriteMappingFile(config, mapping_lines, warnings);
    technique_report.Write(config, output, warnings, true);
    emit(ProgressStage::Write, "APK written without signing");
    emit(ProgressStage::Verify, "ZIP output verified");
    emit(ProgressStage::Complete, "transform complete");
}

} // namespace birch::guard
