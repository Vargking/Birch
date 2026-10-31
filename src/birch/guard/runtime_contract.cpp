#include "runtime_contract.h"

#include "birch/guard/scope.h"
#include "birch/dex/linker.h"

#include <algorithm>
#include <map>
#include <stdexcept>
#include <utility>

namespace birch::guard::detail {

RuntimeContractKeeps RuntimeContractAnalyzer::CollectRuntimeContractKeeps(
    const std::vector<std::reference_wrapper<const dex::DexFile>>& dex_files,
    const ScopeConfig& scope, const dex::DexFile* framework_dex) {
    struct MethodDefinition {
        std::string name;
        std::string proto;
        std::uint32_t access_flags{};
        bool virtual_method{};
    };
    struct FieldDefinition {
        std::string name;
        std::string type;
    };
    struct ClassDefinition {
        std::string superclass;
        std::vector<std::string> interfaces;
        std::vector<MethodDefinition> methods;
        std::vector<FieldDefinition> fields;
    };

    std::map<std::string, ClassDefinition, std::less<>> definitions;
    std::vector<std::reference_wrapper<const dex::DexFile>> graph_files;
    graph_files.reserve(dex_files.size() + (framework_dex == nullptr ? 0U : 1U));
    // Framework definitions are loaded first; application definitions replace
    // them on descriptor collision so app-local metadata remains authoritative.
    if (framework_dex != nullptr) graph_files.emplace_back(*framework_dex);
    graph_files.insert(graph_files.end(), dex_files.begin(), dex_files.end());
    for (const auto dex_reference : graph_files) {
        const auto& dex_file = dex_reference.get();
        for (std::size_t class_index = 0U; class_index < dex_file.classes().size(); ++class_index) {
            const auto& class_def = dex_file.classes()[class_index];
            const auto descriptor = dex_file.descriptor(class_def.class_idx);
            ClassDefinition definition;
            if (class_def.superclass_idx != 0xffffffffU) {
                definition.superclass = dex_file.descriptor(class_def.superclass_idx);
            }
            for (const auto type_idx : dex_file.type_list(class_def.interfaces_off)) {
                definition.interfaces.push_back(dex_file.descriptor(type_idx));
            }
            const auto& data = dex_file.class_data(class_index);
            const auto collect_methods = [&](const std::vector<dex::DexEncodedMethod>& methods,
                                             bool virtual_method) {
                for (const auto& encoded : methods) {
                    const auto& method = dex_file.methods().at(encoded.method_idx);
                    definition.methods.push_back({
                        dex_file.string(method.name_idx), dex_file.proto_key(method.proto_idx),
                        encoded.access_flags, virtual_method});
                }
            };
            collect_methods(data.direct_methods, false);
            collect_methods(data.virtual_methods, true);
            const auto collect_fields = [&](const std::vector<dex::DexEncodedField>& fields) {
                for (const auto& encoded : fields) {
                    const auto& field = dex_file.fields().at(encoded.field_idx);
                    definition.fields.push_back({dex_file.string(field.name_idx),
                                                 dex_file.descriptor(field.type_idx)});
                }
            };
            collect_fields(data.static_fields);
            collect_fields(data.instance_fields);
            definitions.insert_or_assign(descriptor, std::move(definition));
        }
    }

    std::set<std::string, std::less<>> framework_classes;
    std::set<std::string, std::less<>> framework_virtual_keys;
    if (framework_dex != nullptr) {
        for (std::size_t class_index = 0U;
             class_index < framework_dex->classes().size(); ++class_index) {
            const auto& class_def = framework_dex->classes()[class_index];
            const auto owner = framework_dex->descriptor(class_def.class_idx);
            framework_classes.insert(owner);
            const auto& data = framework_dex->class_data(class_index);
            for (const auto* methods : {&data.direct_methods, &data.virtual_methods}) {
                for (const auto& encoded : *methods) {
                    const auto& method = framework_dex->methods().at(encoded.method_idx);
                    if ((encoded.access_flags & 0x0008U) == 0U) {
                        framework_virtual_keys.insert(framework_dex->string(method.name_idx) +
                                                      framework_dex->proto_key(method.proto_idx));
                    }
                }
            }
        }
    }

    const auto is_protected = [&](std::string_view descriptor) {
        return !MatchesAnyScopeRule(descriptor, scope.keep) && MatchesAnyScopeRule(descriptor, scope.protect);
    };
    const auto inherits = [&](const auto& self, std::string_view descriptor,
                              std::string_view contract,
                              std::set<std::string, std::less<>>& visiting) -> bool {
        if (descriptor == contract) return true;
        const auto found = definitions.find(descriptor);
        if (found == definitions.end() || !visiting.insert(std::string(descriptor)).second) {
            return false;
        }
        const auto& definition = found->second;
        auto result = !definition.superclass.empty() &&
                      self(self, definition.superclass, contract, visiting);
        for (const auto& interface_descriptor : definition.interfaces) {
            if (result) break;
            result = self(self, interface_descriptor, contract, visiting);
        }
        visiting.erase(std::string(descriptor));
        return result;
    };
    const auto implements = [&](std::string_view descriptor, std::string_view contract) {
        std::set<std::string, std::less<>> visiting;
        return inherits(inherits, descriptor, contract, visiting);
    };
    const auto touches_framework = [&](const auto& self, std::string_view descriptor,
                                       std::set<std::string, std::less<>>& visiting) -> bool {
        if (framework_classes.contains(std::string(descriptor))) return true;
        const auto found = definitions.find(std::string(descriptor));
        if (found == definitions.end() || !visiting.insert(std::string(descriptor)).second) {
            return false;
        }
        const auto& definition = found->second;
        bool result = !definition.superclass.empty() &&
                      self(self, definition.superclass, visiting);
        for (const auto& interface_descriptor : definition.interfaces) {
            if (result) break;
            result = self(self, interface_descriptor, visiting);
        }
        visiting.erase(std::string(descriptor));
        return result;
    };
    const auto has_external_callback_boundary = [&](const auto& self,
                                                     std::string_view descriptor,
                                                     std::set<std::string, std::less<>>& visiting) -> bool {
        const auto found = definitions.find(descriptor);
        if (found == definitions.end() || !visiting.insert(std::string(descriptor)).second) {
            return false;
        }
        const auto& definition = found->second;
        auto external = !definition.superclass.empty() &&
                        definition.superclass != "Ljava/lang/Object;" &&
                        !definitions.contains(definition.superclass);
        for (const auto& interface_descriptor : definition.interfaces) {
            if (!definitions.contains(interface_descriptor)) {
                external = true;
                break;
            }
        }
        if (!external && !definition.superclass.empty() &&
            definition.superclass != "Ljava/lang/Object;") {
            external = self(self, definition.superclass, visiting);
        }
        if (!external) {
            for (const auto& interface_descriptor : definition.interfaces) {
                if (definitions.contains(interface_descriptor) &&
                    self(self, interface_descriptor, visiting)) {
                    external = true;
                    break;
                }
            }
        }
        visiting.erase(std::string(descriptor));
        return external;
    };

    RuntimeContractKeeps result;
    const dex::DexLinker linker(dex_files, framework_dex);
    const ScopeMatcher matcher(scope);
    const auto can_rename_member = [&](std::string_view owner) {
        return matcher.IsProtected(owner) && matcher.AllowsRenaming(owner) &&
               matcher.IncludesMembers(owner);
    };
    // References through an app subtype may bind to an external/kept ancestor.
    // Include ALL ids, which also covers method handles and encoded metadata.
    // Never rename a symbol whose definition cannot be renamed in the closure.
    for (const auto file : dex_files) {
        const auto& dex_file = file.get();
        for (const auto& method : dex_file.methods()) {
            const auto owner = dex_file.descriptor(method.class_idx);
            if (!can_rename_member(owner)) continue;
            const auto name = dex_file.string(method.name_idx);
            const auto target = linker.ResolveMethod(owner, name, dex_file.proto_key(method.proto_idx));
            if (target.status != dex::ResolutionStatus::Found || target.external ||
                !can_rename_member(target.declaring_class)) {
                if (result.methods.insert(name).second && name != "<init>" && name != "<clinit>") {
                    result.warnings.push_back("automatic runtime keep for inherited/external method reference: " +
                        owner + "->" + name + dex_file.proto_key(method.proto_idx));
                }
            }
        }
        for (const auto& field : dex_file.fields()) {
            const auto owner = dex_file.descriptor(field.class_idx);
            if (!can_rename_member(owner)) continue;
            const auto name = dex_file.string(field.name_idx);
            const auto target = linker.ResolveField(owner, name, dex_file.descriptor(field.type_idx));
            if (target.status != dex::ResolutionStatus::Found || target.external ||
                !can_rename_member(target.declaring_class)) {
                if (result.fields.insert(name).second) {
                    result.warnings.push_back("automatic runtime keep for inherited/external field reference: " +
                        owner + "->" + name + ":" + dex_file.descriptor(field.type_idx));
                }
            }
        }
    }
    for (const auto& [descriptor, definition] : definitions) {
        // Birch-generated/fake classes are implementation detail, even when
        // a structural pass makes them resemble Serializable/Parcelable
        // classes.  Runtime contract preservation applies only to app-owned
        // classes; keeping a generated descriptor would leak the fake
        // namespace and exclude it from the global rename closure.
        if (IsGuardGeneratedDescriptor(descriptor) ||
            descriptor.starts_with("Lx/")) {
            continue;
        }
        if (!is_protected(descriptor)) continue;
        const auto serializable = implements(descriptor, "Ljava/io/Serializable;") ||
                                  implements(descriptor, "Ljava/io/Externalizable;");
        const auto parcelable = implements(descriptor, "Landroid/os/Parcelable;");
        bool contains_native = false;
        std::set<std::string, std::less<>> visiting;
        const auto external_callbacks =
            has_external_callback_boundary(has_external_callback_boundary, descriptor, visiting);
        std::size_t external_names = 0U;
        bool framework_contract = false;
        if (!framework_classes.empty()) {
            std::set<std::string, std::less<>> framework_visiting;
            if (!definition.superclass.empty()) {
                framework_contract = touches_framework(touches_framework,
                                                        definition.superclass,
                                                        framework_visiting);
            }
            for (const auto& interface_descriptor : definition.interfaces) {
                if (framework_contract) break;
                framework_contract = touches_framework(touches_framework,
                                                       interface_descriptor,
                                                       framework_visiting);
            }
        }
        for (const auto& method : definition.methods) {
            constexpr std::uint32_t kNative = 0x0100U;
            if ((method.access_flags & kNative) != 0U) {
                contains_native = true;
                result.methods.insert(method.name);
            }
            const auto serialization_hook = serializable && (
                (method.name == "writeObject" && method.proto == "(Ljava/io/ObjectOutputStream;)V") ||
                (method.name == "readObject" && method.proto == "(Ljava/io/ObjectInputStream;)V") ||
                (method.name == "readObjectNoData" && method.proto == "()V") ||
                (method.name == "writeReplace" && method.proto == "()Ljava/lang/Object;") ||
                (method.name == "readResolve" && method.proto == "()Ljava/lang/Object;") ||
                (method.name == "writeExternal" && method.proto == "(Ljava/io/ObjectOutput;)V") ||
                (method.name == "readExternal" && method.proto == "(Ljava/io/ObjectInput;)V"));
            const auto object_contract = method.virtual_method && (
                (method.name == "equals" && method.proto == "(Ljava/lang/Object;)Z") ||
                (method.name == "hashCode" && method.proto == "()I") ||
                (method.name == "toString" && method.proto == "()Ljava/lang/String;") ||
                (method.name == "clone" && method.proto == "()Ljava/lang/Object;") ||
                (method.name == "finalize" && method.proto == "()V"));
            const auto framework_override = framework_contract && method.virtual_method &&
                framework_virtual_keys.contains(method.name + method.proto);
            if (serialization_hook || object_contract || framework_override ||
                (external_callbacks && method.virtual_method)) {
                if (result.methods.insert(method.name).second &&
                    external_callbacks && method.virtual_method) {
                    ++external_names;
                }
            }
        }
        for (const auto& field : definition.fields) {
            if ((parcelable && field.name == "CREATOR" &&
                 field.type == "Landroid/os/Parcelable$Creator;") ||
                (serializable && (field.name == "serialVersionUID" ||
                                  field.name == "serialPersistentFields"))) {
                result.fields.insert(field.name);
            }
        }
        if (contains_native || serializable || parcelable) {
            result.classes.insert(descriptor);
        }
        if (contains_native) {
            result.warnings.push_back("automatic runtime keep for JNI class and native method names: " +
                                      descriptor);
        }
        if (serializable) {
            result.warnings.push_back("automatic runtime keep for Java serialization contract: " +
                                      descriptor);
        }
        if (parcelable) {
            result.warnings.push_back("automatic runtime keep for Parcelable contract: " + descriptor);
        }
        if (external_names != 0U) {
            result.warnings.push_back(
                "automatic runtime keep for " + std::to_string(external_names) +
                " virtual callback name(s) on unresolved external hierarchy: " + descriptor);
        }
    }
    return result;
}

} // namespace birch::guard::detail

