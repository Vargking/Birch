#include "rename_planner.h"

#include "rename_names.h"
#include "runtime_contract.h"
#include "package_access.h"
#include "method_conflicts.h"
#include "birch/guard/scope.h"
#include "birch/dex/remap.h"
#include "birch/utils/hash.h"

#include <algorithm>
#include <map>
#include <stdexcept>
#include <utility>

namespace birch::guard::detail {

ReflectionRenamePlan RenamePlanner::BuildReflectionRenamePlan(
    const GlobalRenamePlan& rename_plan) {
    ReflectionRenamePlan result;
    result.classes = rename_plan.classes;
    result.methods = rename_plan.methods;
    result.fields = rename_plan.fields;
    return result;
}

void RenamePlanner::MergeReflectionRenamePlan(ReflectionRenamePlan& destination,
                               const ReflectionRenamePlan& source) {
    const auto merge = [](auto& output, const auto& input,
                          std::string_view domain) {
        for (const auto& [name, replacement] : input) {
            const auto [found, inserted] = output.emplace(name, replacement);
            if (!inserted && found->second != replacement) {
                throw std::logic_error(
                    "inconsistent used reflection " + std::string(domain) +
                    " rename for " + name);
            }
        }
    };
    merge(destination.classes, source.classes, "class");
    merge(destination.methods, source.methods, "method");
    merge(destination.fields, source.fields, "field");
}

bool RenamePlanner::EmptyReflectionRenamePlan(const ReflectionRenamePlan& plan) {
    return plan.classes.empty() && plan.methods.empty() &&
           plan.fields.empty();
}

GlobalRenamePlan RenamePlanner::BuildReflectionRenameLocks(
    const ReflectionRenamePlan& plan) {
    GlobalRenamePlan result;
    result.classes = plan.classes;
    result.methods = plan.methods;
    result.fields = plan.fields;
    return result;
}

void RenamePlanner::ValidateStablePreModelRenamePlan(
    const GlobalRenamePlan& before_model,
    const GlobalRenamePlan& final_plan) {
    const auto validate = [](const auto& before, const auto& after,
                             std::string_view domain) {
        for (const auto& [source, expected] : before) {
            const auto found = after.find(source);
            if (found != after.end() && found->second != expected) {
                throw std::runtime_error(
                    "model lowering changed the precomputed reflection " +
                    std::string(domain) + " rename for " + source);
            }
        }
    };
    validate(before_model.classes, final_plan.classes, "class");
    validate(before_model.methods, final_plan.methods, "method");
    validate(before_model.fields, final_plan.fields, "field");
}

GlobalRenamePlan RenamePlanner::BuildGlobalRenamePlan(
    const std::vector<std::reference_wrapper<const dex::DexFile>>& dex_files,
    const ScopeConfig& scope, const RenameConfig& rename, std::uint64_t seed,
    bool rename_classes, bool rename_methods, bool rename_fields,
    bool overload_induction, double overload_intensity,
    const dex::DexFile* framework_dex,
    const GlobalRenamePlan* locked_plan) {
    GlobalRenamePlan plan;
    const ScopeMatcher scope_matcher(scope);
    const auto runtime_keeps = RuntimeContractAnalyzer::CollectRuntimeContractKeeps(dex_files, scope,
                                                            framework_dex);
    plan.warnings = runtime_keeps.warnings;
    const auto dictionary = NameGenerator::DictionaryTokens(rename.dictionary);
    std::set<std::string, std::less<>> protected_classes;
    std::set<std::string, std::less<>> used_names;
    std::set<std::string, std::less<>> protected_method_names;
    std::set<std::string, std::less<>> unprotected_method_names;
    std::set<std::string, std::less<>> protected_field_names;
    std::set<std::string, std::less<>> unprotected_field_names;
    std::set<std::string, std::less<>> all_method_names;
    std::set<std::string, std::less<>> all_field_names;
    auto method_conflicts = MethodConflictPlanner::Build(dex_files, framework_dex);
    for (const auto dex_reference : dex_files) {
        const auto& dex_file = dex_reference.get();
        for (const auto& value : dex_file.strings()) used_names.insert(value.mutf8);
        for (std::size_t class_index = 0U;
             class_index < dex_file.classes().size(); ++class_index) {
            const auto& definition = dex_file.classes()[class_index];
            const auto descriptor = dex_file.descriptor(definition.class_idx);
            if (scope_matcher.IsProtected(descriptor) &&
                scope_matcher.AllowsRenaming(descriptor)) {
                protected_classes.insert(descriptor);
            }
        }
        for (const auto& method : dex_file.methods()) {
            const auto name = dex_file.string(method.name_idx);
            if (NameGenerator::IsSpecialMethod(name)) continue;
            all_method_names.insert(name);
            const auto owner = dex_file.descriptor(method.class_idx);
            if (scope_matcher.IsProtected(owner) &&
                scope_matcher.AllowsRenaming(owner) &&
                scope_matcher.IncludesMembers(owner)) {
                protected_method_names.insert(name);
            } else {
                unprotected_method_names.insert(name);
            }
        }
        for (const auto& field : dex_file.fields()) {
            const auto name = dex_file.string(field.name_idx);
            all_field_names.insert(name);
            const auto owner = dex_file.descriptor(field.class_idx);
            if (scope_matcher.IsProtected(owner) &&
                scope_matcher.AllowsRenaming(owner) &&
                scope_matcher.IncludesMembers(owner)) {
                protected_field_names.insert(name);
            } else {
                unprotected_field_names.insert(name);
            }
        }
    }
    if (framework_dex != nullptr) {
        // Framework names are reserved globally.  A generated short name that
        // accidentally matches an inherited Android method can silently turn
        // an unrelated app method into an override.
        for (const auto& value : framework_dex->strings()) {
            used_names.insert(value.mutf8);
        }
    }
    if (locked_plan != nullptr) {
        for (const auto* mappings : {&locked_plan->classes,
                                     &locked_plan->methods,
                                     &locked_plan->fields}) {
            for (const auto& [source, target] : *mappings) {
                (void)source;
                used_names.insert(target);
            }
        }
    }
    if (rename_classes) {
        auto moving_classes = protected_classes;
        for (const auto& kept : runtime_keeps.classes) moving_classes.erase(kept);
        const auto package_prefixes = PackageAccessPlanner::RequiredPrefixes(dex_files, framework_dex, moving_classes);
        for (const auto& descriptor : protected_classes) {
            const auto locked = locked_plan == nullptr ?
                std::map<std::string, std::string, std::less<>>::const_iterator{} :
                locked_plan->classes.find(descriptor);
            if (runtime_keeps.classes.contains(descriptor)) {
                if (locked_plan != nullptr &&
                    locked != locked_plan->classes.end()) {
                    throw std::runtime_error(
                        "pre-model class rename became runtime-kept: " +
                        descriptor);
                }
                continue;
            }
            if (locked_plan != nullptr && locked != locked_plan->classes.end()) {
                if (const auto prefix = package_prefixes.find(descriptor);
                    prefix != package_prefixes.end() &&
                    locked->second.substr(0, locked->second.rfind('/') + 1U) != prefix->second) {
                    throw std::runtime_error("locked class rename breaks package access: " + descriptor);
                }
                plan.classes.emplace(descriptor, locked->second);
                continue;
            }
            plan.classes.emplace(
                descriptor,
                NameGenerator::StableDexName(descriptor,
                    package_prefixes.contains(descriptor) ? package_prefixes.at(descriptor) :
                        NameGenerator::NormalizedRenamePrefix(rename.package_prefix), dictionary,
                              seed ^ utils::StableHash64(descriptor, seed), used_names));
            if (package_prefixes.contains(descriptor)) {
                plan.warnings.push_back("class simple name obfuscated in original package to preserve access to kept classes: " + descriptor);
            }
        }
    }
    if (rename_methods) {
        std::vector<std::string> renameable;
        for (const auto& name : protected_method_names) {
            const auto locked = locked_plan == nullptr ?
                std::map<std::string, std::string, std::less<>>::const_iterator{} :
                locked_plan->methods.find(name);
            if (runtime_keeps.methods.contains(name)) {
                if (locked_plan != nullptr &&
                    locked != locked_plan->methods.end()) {
                    throw std::runtime_error(
                        "pre-model method rename became runtime-kept: " + name);
                }
                continue;
            }
            if (unprotected_method_names.contains(name) || all_field_names.contains(name)) {
                if (locked_plan != nullptr &&
                    locked != locked_plan->methods.end()) {
                    throw std::runtime_error(
                        "pre-model method rename became globally unsafe: " + name);
                }
                plan.warnings.push_back(
                    "method name kept globally because it is shared with an excluded owner or field: " +
                    name);
                continue;
            }
            renameable.push_back(name);
        }
        std::sort(renameable.begin(), renameable.end(), [&](const auto& left, const auto& right) {
            const auto left_degree = method_conflicts[left].size();
            const auto right_degree = method_conflicts[right].size();
            return left_degree != right_degree ? left_degree > right_degree : left < right;
        });
        std::vector<std::string> palette;
        std::map<std::string, std::size_t, std::less<>> colors;
        std::map<std::string, std::size_t, std::less<>> locked_colors;
        if (locked_plan != nullptr) {
            for (const auto& name : renameable) {
                const auto locked = locked_plan->methods.find(name);
                if (locked == locked_plan->methods.end()) continue;
                const auto [color, inserted] = locked_colors.emplace(
                    locked->second, locked_colors.size());
                if (inserted) palette.push_back(locked->second);
                colors.emplace(name, color->second);
                plan.methods.emplace(name, locked->second);
            }
            for (const auto& [name, color] : colors) {
                for (const auto& conflict : method_conflicts[name]) {
                    const auto found = colors.find(conflict);
                    if (found != colors.end() && found->second == color) {
                        throw std::runtime_error(
                            "model lowering made locked overload names conflict: " +
                            name + " and " + conflict);
                    }
                }
            }
        }
        for (const auto& name : renameable) {
            if (colors.contains(name)) continue;
            const auto hash = utils::StableHash64(name, seed ^ 0x6f7665726c6f6164ULL);
            const auto sample = static_cast<double>(hash >> 11U) /
                                static_cast<double>(std::uint64_t{1} << 53U);
            const auto may_reuse = overload_induction && sample <= overload_intensity;
            std::set<std::size_t> unavailable;
            for (const auto& conflict : method_conflicts[name]) {
                const auto found = colors.find(conflict);
                if (found != colors.end()) unavailable.insert(found->second);
            }
            std::size_t color = palette.size();
            if (may_reuse) {
                for (std::size_t candidate = 0U; candidate < palette.size(); ++candidate) {
                    if (!unavailable.contains(candidate)) { color = candidate; break; }
                }
            }
            if (color == palette.size()) {
                palette.push_back(NameGenerator::StableMemberName(
                    "overload-color-" + std::to_string(color), dictionary,
                    seed ^ (0x6d6574686f64ULL + color), used_names));
            }
            colors.emplace(name, color);
            plan.methods.emplace(name, palette[color]);
        }
    }
    if (rename_fields) {
        for (const auto& name : protected_field_names) {
            const auto locked = locked_plan == nullptr ?
                std::map<std::string, std::string, std::less<>>::const_iterator{} :
                locked_plan->fields.find(name);
            if (runtime_keeps.fields.contains(name)) {
                if (locked_plan != nullptr &&
                    locked != locked_plan->fields.end()) {
                    throw std::runtime_error(
                        "pre-model field rename became runtime-kept: " + name);
                }
                continue;
            }
            if (unprotected_field_names.contains(name) || all_method_names.contains(name)) {
                if (locked_plan != nullptr &&
                    locked != locked_plan->fields.end()) {
                    throw std::runtime_error(
                        "pre-model field rename became globally unsafe: " + name);
                }
                plan.warnings.push_back(
                    "field name kept globally because it is shared with an excluded owner or method: " +
                    name);
                continue;
            }
            if (locked_plan != nullptr && locked != locked_plan->fields.end()) {
                plan.fields.emplace(name, locked->second);
                continue;
            }
            const auto replacement = NameGenerator::StableMemberName(
                name, dictionary, seed ^ utils::StableHash64(name, seed ^ 0x6669656c64ULL),
                used_names);
            plan.fields.emplace(name, replacement);
        }
    }
    return plan;
}

DexRenameResult RenamePlanner::RenameDex(const dex::DexFile& dex, const ScopeConfig& scope,
                          const RenameConfig& rename, std::uint64_t seed,
                          bool rename_classes, bool rename_methods, bool rename_fields,
                          const GlobalRenamePlan* global_plan) {
    if (global_plan == nullptr) {
        const auto plan = BuildGlobalRenamePlan({dex}, scope, rename, seed,
            rename_classes, rename_methods, rename_fields, rename.overload_methods, 1.0);
        return RenameDex(dex, scope, rename, seed, rename_classes, rename_methods, rename_fields, &plan);
    }
    std::set<std::string, std::less<>> protected_descriptors;
    for (std::size_t i = 0; i < dex.classes().size(); ++i) {
        const auto descriptor = dex.descriptor(dex.classes()[i].class_idx);
        const ScopeMatcher scope_matcher(scope);
        if (scope_matcher.IsProtected(descriptor) &&
            scope_matcher.AllowsRenaming(descriptor)) {
            protected_descriptors.insert(descriptor);
        }
    }
    std::map<std::uint32_t, std::pair<std::string, std::uint32_t>> replacements;
    std::map<std::string, std::string, std::less<>> class_map;
    std::vector<std::string> mapping_lines;
    std::vector<std::string> warnings;
    std::map<std::uint32_t, std::string> desired_member_names;
    if (rename_classes) {
        for (const auto& type : dex.types()) {
            const auto descriptor = dex.string(type.descriptor_idx);
            if (descriptor.starts_with('[')) {
                const auto dimensions = descriptor.find_first_not_of('[');
                if (dimensions != std::string::npos) {
                    const auto element = global_plan->classes.find(descriptor.substr(dimensions));
                    if (element != global_plan->classes.end()) {
                        const auto replacement = descriptor.substr(0U, dimensions) + element->second;
                        replacements.insert_or_assign(type.descriptor_idx,
                            std::make_pair(replacement, NameGenerator::Mutf8Utf16Length(replacement)));
                    }
                }
                continue;
            }
            const auto planned = global_plan->classes.find(descriptor);
            if (planned != global_plan->classes.end()) {
                replacements.insert_or_assign(
                    type.descriptor_idx,
                    std::make_pair(planned->second, NameGenerator::Mutf8Utf16Length(planned->second)));
                if (protected_descriptors.contains(descriptor)) {
                    class_map.emplace(descriptor, planned->second);
                }
            }
        }
    }
    std::set<std::uint32_t> protected_method_string_ids;
    for (const auto& method : dex.methods()) {
        const auto owner = dex.descriptor(method.class_idx);
        if (NameGenerator::IsSpecialMethod(dex.string(method.name_idx))) continue;
        const ScopeMatcher scope_matcher(scope);
        if (scope_matcher.IsProtected(owner) && scope_matcher.AllowsRenaming(owner) &&
            scope_matcher.IncludesMembers(owner)) protected_method_string_ids.insert(method.name_idx);
    }
    std::set<std::uint32_t> protected_field_string_ids;
    for (const auto& field : dex.fields()) {
        const auto owner = dex.descriptor(field.class_idx);
        const ScopeMatcher scope_matcher(scope);
        if (scope_matcher.IsProtected(owner) && scope_matcher.AllowsRenaming(owner) &&
            scope_matcher.IncludesMembers(owner)) protected_field_string_ids.insert(field.name_idx);
    }
    for (const auto string_idx : protected_method_string_ids) {
        if (!rename_methods) break;
        const auto& value = dex.strings()[string_idx];
        const auto planned = global_plan->methods.find(value.mutf8);
        if (planned == global_plan->methods.end()) continue;
        desired_member_names.insert_or_assign(string_idx, planned->second);
        mapping_lines.push_back(value.mutf8 + " -> " + planned->second);
    }
    for (const auto string_idx : protected_field_string_ids) {
        if (!rename_fields) break;
        const auto& value = dex.strings()[string_idx];
        const auto planned = global_plan->fields.find(value.mutf8);
        if (planned == global_plan->fields.end()) continue;
        desired_member_names.insert_or_assign(string_idx, planned->second);
        mapping_lines.push_back(value.mutf8 + " -> " + planned->second);
    }
    std::vector<std::uint32_t> string_aliases(dex.strings().size());
    for (std::size_t i = 0U; i < string_aliases.size(); ++i) {
        string_aliases[i] = static_cast<std::uint32_t>(i);
    }
    std::map<std::string, std::vector<std::uint32_t>, std::less<>> alias_groups;
    for (const auto& [string_idx, target] : desired_member_names) {
        alias_groups[target].push_back(string_idx);
    }
    for (auto& [target, indices] : alias_groups) {
        std::sort(indices.begin(), indices.end());
        auto representative = indices.front();
        const auto existing = std::find_if(
            dex.strings().begin(), dex.strings().end(),
            [&](const auto& value) {
                if (value.mutf8 != target) return false;
                const auto string_idx = static_cast<std::uint32_t>(
                    &value - dex.strings().data());
                if (replacements.contains(string_idx)) return false;
                const auto desired = desired_member_names.find(string_idx);
                return desired == desired_member_names.end() ||
                       desired->second == target;
            });
        if (existing != dex.strings().end()) {
            representative = static_cast<std::uint32_t>(
                existing - dex.strings().begin());
        } else {
            if (replacements.contains(representative)) {
                throw std::runtime_error(
                    "class/member rename requires incompatible string roles");
            }
            replacements.emplace(
                representative,
                std::make_pair(target, NameGenerator::Mutf8Utf16Length(target)));
        }
        for (const auto string_idx : indices) string_aliases[string_idx] = representative;
    }
    for (const auto& [old_name, new_name] : class_map) mapping_lines.push_back(old_name + " -> " + new_name);
    bool has_aliases = false;
    for (std::size_t index = 0; index < string_aliases.size(); ++index) {
        if (string_aliases[index] != index) { has_aliases = true; break; }
    }
    if (replacements.empty() && !has_aliases) return {dex.Write(), 0U, 0U, 0U, {}, std::move(mapping_lines), std::move(warnings)};
    auto rewritten_bytes = dex.ReplaceStrings(replacements);
    auto rewritten_dex = dex::DexFile::Parse(rewritten_bytes);
    const auto remap = dex::BuildCanonicalRemap(rewritten_dex, {}, string_aliases);
    rewritten_bytes = dex::ApplyIdRemap(rewritten_dex, remap);
    return {std::move(rewritten_bytes), class_map.size(), protected_method_string_ids.size(), protected_field_string_ids.size(), class_map, std::move(mapping_lines), std::move(warnings)};
}

} // namespace birch::guard::detail

