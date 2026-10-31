#include "birch/dex/linkage_verifier.h"

#include "birch/dex/code.h"
#include "inheritance_verifier.h"
#include "linkage_names.h"

#include <stdexcept>

namespace birch::dex {
namespace {

using detail::Package;
using detail::Rename;
using detail::Translate;

bool Accessible(const DexLinker& linker, std::string_view caller,
                const MemberResolution& target) {
    if ((target.access_flags & 1U) != 0U || caller == target.declaring_class) return true;
    if ((target.access_flags & 2U) != 0U) return false;
    if (Package(caller) == Package(target.declaring_class)) return true;
    return (target.access_flags & 4U) != 0U && linker.IsSubclass(caller, target.declaring_class);
}

} // namespace

LinkageReport LinkageVerifier::Analyze(
    const std::vector<std::reference_wrapper<const DexFile>>& files,
    const DexFile* framework, const LinkageRenames& renames) {
    const DexLinker linker(files, framework);
    LinkageReport report;
    for (const auto& [source, target] : renames.classes) {
        if (source != target) report.relocated_classes.insert(source);
    }
    const auto record = [&](const std::string& key, const MemberResolution& target) {
        if (target.status == ResolutionStatus::Found) {
            report.resolved.insert(key);
            report.bindings[key].insert(Translate(target.declaring_class, renames.classes));
        }
        else {
            report.unresolved.insert(key);
            if (target.status == ResolutionStatus::Missing) report.failures.insert("missing " + key);
        }
    };
    for (const auto file : files) {
        const auto& dex = file.get();
        for (const auto& type : dex.types()) {
            auto descriptor = dex.string(type.descriptor_idx);
            while (descriptor.starts_with('[')) descriptor.erase(0U, 1U);
            if (!descriptor.starts_with('L')) continue;
            const auto key = "type " + Translate(descriptor, renames.classes);
            if (linker.FindClass(descriptor) != nullptr) report.resolved.insert(key);
            else report.unresolved.insert(key);
        }
        std::vector<MemberResolution> methods;
        std::vector<std::string> method_keys;
        for (const auto& method : dex.methods()) {
            const auto owner = dex.descriptor(method.class_idx);
            const auto name = dex.string(method.name_idx);
            const auto proto = dex.proto_key(method.proto_idx);
            methods.push_back(linker.ResolveMethod(owner, name, proto));
            method_keys.push_back("method " + Translate(owner, renames.classes) + "->" +
                Rename(name, renames.methods) + Translate(proto, renames.classes));
            record(method_keys.back(), methods.back());
        }
        std::vector<MemberResolution> fields;
        std::vector<std::string> field_keys;
        for (const auto& field : dex.fields()) {
            const auto owner = dex.descriptor(field.class_idx);
            const auto name = dex.string(field.name_idx);
            const auto type = dex.descriptor(field.type_idx);
            fields.push_back(linker.ResolveField(owner, name, type));
            field_keys.push_back("field " + Translate(owner, renames.classes) + "->" +
                Rename(name, renames.fields) + ":" + Translate(type, renames.classes));
            record(field_keys.back(), fields.back());
        }
        const auto require = [&](const std::string& key) {
            if (!report.resolved.contains(key)) report.runtime_unresolved.insert(key);
        };
        const auto require_type = [&](std::string descriptor) {
            while (descriptor.starts_with('[')) descriptor.erase(0U, 1U);
            if (descriptor.starts_with('L')) require("type " + Translate(descriptor, renames.classes));
        };
        const auto require_proto = [&](std::string_view proto) {
            for (auto start = proto.find('L'); start != std::string_view::npos;) {
                const auto end = proto.find(';', start);
                if (end == std::string_view::npos) break;
                require_type(std::string(proto.substr(start, end + 1U - start)));
                start = proto.find('L', end + 1U);
            }
        };
        for (const auto& handle : dex.method_handles()) {
            require(handle.handle_type <= 3U ? field_keys.at(handle.member_idx) : method_keys.at(handle.member_idx));
        }
        const auto check = [&](const MemberResolution& target, const std::string& key,
                               std::string_view caller, bool is_static, int kind,
                               std::string_view symbolic_owner) {
            if (target.status != ResolutionStatus::Found) return;
            const auto prefix = Translate(caller, renames.classes) + ": ";
            if (((target.access_flags & 8U) != 0U) != is_static) {
                report.failures.insert(prefix + "static/instance mismatch " + key);
            }
            if (kind == 1 && !is_static && target.virtual_method) {
                report.failures.insert(prefix + "direct invoke of virtual " + key);
            }
            if ((kind == 2 || kind == 3) && !target.virtual_method) {
                report.failures.insert(prefix + "virtual/interface invoke of direct " + key);
            }
            const auto* owner_class = linker.FindClass(symbolic_owner);
            if (owner_class != nullptr) {
                const auto interface_owner = (owner_class->access_flags & 0x0200U) != 0U;
                if ((kind == 2 && interface_owner) || (kind == 3 && !interface_owner)) {
                    report.failures.insert(prefix + "class/interface invoke mismatch " + key);
                }
                if ((owner_class->access_flags & 1U) == 0U &&
                    Package(caller) != Package(symbolic_owner)) {
                    report.failures.insert(prefix + "inaccessible symbolic class " + key);
                }
            }
            if (!Accessible(linker, caller, target)) {
                report.failures.insert(prefix + "inaccessible member " + key);
            }
        };
        // Handles have independent invocation/access kinds, even if never used
        // in a conventional invoke instruction (bootstrap/encoded-value paths).
        for (const auto& handle : dex.method_handles()) {
            const auto index = handle.member_idx;
            if (handle.handle_type <= 3U) {
                const auto& target = fields.at(index);
                const auto is_static = handle.handle_type <= 1U;
                if (target.status == ResolutionStatus::Found &&
                    (((target.access_flags & 8U) != 0U) != is_static)) {
                    report.failures.insert("handle static/instance mismatch " + field_keys.at(index));
                }
            } else {
                const auto& target = methods.at(index);
                const auto kind = handle.handle_type;
                if (target.status == ResolutionStatus::Found &&
                    (((target.access_flags & 8U) != 0U) != (kind == 4U) ||
                     ((kind == 5U || kind == 8U) && !target.virtual_method))) {
                    report.failures.insert("handle invocation mismatch " + method_keys.at(index));
                }
            }
        }
        for (std::size_t class_index = 0; class_index < dex.classes().size(); ++class_index) {
            const auto& definition = dex.classes()[class_index];
            const auto caller = dex.descriptor(definition.class_idx);
            if (definition.superclass_idx != 0xffffffffU) require_type(dex.descriptor(definition.superclass_idx));
            for (const auto type : dex.type_list(definition.interfaces_off)) require_type(dex.descriptor(type));
            const auto& data = dex.class_data(class_index);
            for (const auto* group : {&data.static_fields, &data.instance_fields}) {
                for (const auto& field : *group) require_type(dex.descriptor(dex.fields().at(field.field_idx).type_idx));
            }
            for (const auto* group : {&data.direct_methods, &data.virtual_methods}) {
                for (const auto& encoded : *group) {
                    require_proto(dex.proto_key(dex.methods().at(encoded.method_idx).proto_idx));
                    if (encoded.code_off == 0U) continue;
                    const auto code = DecodeCodeItem(dex, encoded.code_off);
                    for (const auto& region : code.tries) {
                        for (const auto& handler : region.handlers) {
                            if (handler.type_idx) require_type(dex.descriptor(*handler.type_idx));
                        }
                    }
                    for (const auto& instruction : code.instructions) {
                        const auto opcode = instruction.opcode;
                        if ((opcode >= 0x6eU && opcode <= 0x72U) ||
                            (opcode >= 0x74U && opcode <= 0x78U)) {
                            const auto index = instruction.code_units.at(1);
                            const auto& method = dex.methods().at(index);
                            require(method_keys.at(index));
                            require_type(dex.descriptor(method.class_idx));
                            require_proto(dex.proto_key(method.proto_idx));
                            const auto base = opcode >= 0x74U ? opcode - 6U : opcode;
                            const auto kind = base == 0x70U ? 1 : base == 0x6eU ? 2 : base == 0x72U ? 3 : 0;
                            check(methods.at(index), method_keys.at(index), caller, base == 0x71U,
                                  kind, dex.descriptor(method.class_idx));
                            if (base == 0x6fU) {
                                const auto* current = linker.FindClass(caller);
                                const auto owner = dex.descriptor(method.class_idx);
                                const auto* target_class = linker.FindClass(owner);
                                // invoke-super may target a direct superinterface on newer DEX.
                                if (current != nullptr && target_class != nullptr &&
                                    (target_class->access_flags & 0x0200U) == 0U &&
                                    !linker.IsSubclass(current->superclass, owner)) {
                                    report.failures.insert(Translate(caller, renames.classes) +
                                        ": unrelated invoke-super " + method_keys.at(index));
                                }
                            }
                        } else if (opcode >= 0x52U && opcode <= 0x6dU) {
                            const auto index = instruction.code_units.at(1);
                            const auto& field = dex.fields().at(index);
                            require(field_keys.at(index));
                            require_type(dex.descriptor(field.class_idx));
                            require_type(dex.descriptor(field.type_idx));
                            check(fields.at(index), field_keys.at(index), caller, opcode >= 0x60U,
                                  0, dex.descriptor(field.class_idx));
                        } else if (opcode == 0x1cU || opcode == 0x1fU || opcode == 0x20U ||
                                   (opcode >= 0x22U && opcode <= 0x25U)) {
                            auto type = dex.descriptor(instruction.code_units.at(1));
                            require_type(type);
                            while (type.starts_with('[')) type.erase(0U, 1U);
                            const auto* target = linker.FindClass(type);
                            if (target != nullptr && (target->access_flags & 1U) == 0U &&
                                Package(caller) != Package(type)) {
                                report.failures.insert(Translate(caller, renames.classes) +
                                    ": inaccessible type " + Translate(type, renames.classes));
                            }
                        }
                    }
                }
            }
        }
    }
    detail::InheritanceVerifier::Analyze(linker, files, renames, report);
    return report;
}

void LinkageVerifier::VerifyNoNewFailures(const LinkageReport& baseline,
    const std::vector<std::reference_wrapper<const DexFile>>& output,
    const DexFile* framework) {
    const auto report = Analyze(output, framework);
    for (const auto& failure : report.failures) {
        if (baseline.failures.contains(failure)) continue;
        if (failure.starts_with("missing ") && baseline.unresolved.contains(failure.substr(8U))) continue;
        throw std::runtime_error("DEX linkage verification failed: " + failure);
    }
    for (const auto& key : report.unresolved) {
        if (key.starts_with("type ") && baseline.relocated_classes.contains(key.substr(5U))) {
            throw std::runtime_error("DEX linkage verification found stale renamed " + key);
        }
        if (baseline.resolved.contains(key)) {
            throw std::runtime_error("DEX linkage verification lost a resolved binding: " + key);
        }
    }
    if (framework != nullptr) for (const auto& key : report.runtime_unresolved) {
        if (!baseline.runtime_unresolved.contains(key)) {
            throw std::runtime_error("DEX linkage verification introduced unresolved executable reference: " + key);
        }
    }
    for (const auto& [key, targets] : report.bindings) {
        const auto before = baseline.bindings.find(key);
        if (before != baseline.bindings.end() && before->second != targets) {
            throw std::runtime_error("DEX linkage verification changed declaring class: " + key);
        }
    }
    for (const auto& relation : report.inheritance) {
        const auto& [child, parent, signature] = relation;
        if (baseline.application_classes.contains(child) &&
            baseline.application_classes.contains(parent) && !baseline.inheritance.contains(relation)) {
            throw std::runtime_error("DEX linkage verification introduced method inheritance: " +
                child + "->" + signature + " over " + parent);
        }
    }
    for (const auto& relation : baseline.inheritance) {
        const auto& [child, parent, signature] = relation;
        if (report.application_classes.contains(child) && report.application_classes.contains(parent) &&
            !report.inheritance.contains(relation)) {
            throw std::runtime_error("DEX linkage verification lost method inheritance: " +
                child + "->" + signature + " over " + parent);
        }
    }
}

} // namespace birch::dex
