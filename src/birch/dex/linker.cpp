#include "birch/dex/linker.h"

#include <stdexcept>
#include <utility>

namespace birch::dex {

DexLinker::DexLinker(
    const std::vector<std::reference_wrapper<const DexFile>>& files,
    const DexFile* framework) {
    if (framework != nullptr) AddFile(*framework, true);
    for (const auto file : files) AddFile(file.get(), false);
}

void DexLinker::AddFile(const DexFile& file, bool external) {
    for (std::size_t index = 0; index < file.classes().size(); ++index) {
        const auto& spec = file.classes()[index];
        const auto owner = file.descriptor(spec.class_idx);
        if (const auto found = classes_.find(owner);
            found != classes_.end() && !found->second.external) {
            throw std::runtime_error("duplicate application class across DEX files: " + owner);
        }
        LinkClass definition;
        definition.access_flags = spec.access_flags;
        definition.external = external;
        if (spec.superclass_idx != 0xffffffffU) {
            definition.superclass = file.descriptor(spec.superclass_idx);
        }
        for (const auto type : file.type_list(spec.interfaces_off)) {
            definition.interfaces.push_back(file.descriptor(type));
        }
        const auto& data = file.class_data(index);
        for (const auto* methods : {&data.direct_methods, &data.virtual_methods}) {
            for (const auto& encoded : *methods) {
                const auto& method = file.methods().at(encoded.method_idx);
                definition.methods.emplace(
                    file.string(method.name_idx) + file.proto_key(method.proto_idx),
                    MemberResolution{ResolutionStatus::Found, owner, encoded.access_flags,
                                     methods == &data.virtual_methods, external});
            }
        }
        for (const auto* fields : {&data.static_fields, &data.instance_fields}) {
            for (const auto& encoded : *fields) {
                const auto& field = file.fields().at(encoded.field_idx);
                definition.fields.emplace(
                    file.string(field.name_idx) + ":" + file.descriptor(field.type_idx),
                    MemberResolution{ResolutionStatus::Found, owner, encoded.access_flags,
                                     false, external});
            }
        }
        classes_.insert_or_assign(owner, std::move(definition));
    }
}

const LinkClass* DexLinker::FindClass(std::string_view descriptor) const {
    const auto found = classes_.find(descriptor);
    return found == classes_.end() ? nullptr : &found->second;
}

MemberResolution DexLinker::Lookup(std::string_view owner, const std::string& key,
    bool field, bool inherit, std::set<std::string, std::less<>>& visiting) const {
    const auto* definition = FindClass(owner);
    if (definition == nullptr) {
        return {ResolutionStatus::UnknownExternal, std::string(owner), 0U, false, true};
    }
    if (!visiting.insert(std::string(owner)).second) return {};
    const auto& members = field ? definition->fields : definition->methods;
    if (const auto member = members.find(key); member != members.end()) {
        visiting.erase(std::string(owner));
        return member->second;
    }
    MemberResolution result;
    const auto search = [&](std::string_view parent, bool interface_parent) {
        if (parent.empty() || result.status == ResolutionStatus::Found) return;
        auto candidate = Lookup(parent, key, field, true, visiting);
        // Static/private interface methods do not participate in inheritance.
        if (!field && interface_parent && candidate.status == ResolutionStatus::Found &&
            (candidate.access_flags & (0x0008U | 0x0002U)) != 0U) return;
        if (candidate.status == ResolutionStatus::Found ||
            candidate.status == ResolutionStatus::UnknownExternal) result = std::move(candidate);
    };
    if (inherit) {
        // Field resolution: declaration, superinterfaces, superclass.
        // Class method resolution: class/superclasses, then superinterfaces.
        if (!field) search(definition->superclass, false);
        for (const auto& interface : definition->interfaces) search(interface, true);
        if (field) search(definition->superclass, false);
    }
    visiting.erase(std::string(owner));
    return result;
}

MemberResolution DexLinker::ResolveMethod(std::string_view owner,
    std::string_view name, std::string_view proto) const {
    std::set<std::string, std::less<>> visiting;
    // Constructors/class initializers are NEVER inherited.
    return Lookup(owner, std::string(name) + std::string(proto), false,
                  name != "<init>" && name != "<clinit>", visiting);
}

MemberResolution DexLinker::ResolveField(std::string_view owner,
    std::string_view name, std::string_view type) const {
    std::set<std::string, std::less<>> visiting;
    return Lookup(owner, std::string(name) + ":" + std::string(type), true, true, visiting);
}

bool DexLinker::IsSubclass(std::string_view child, std::string_view parent) const {
    std::vector<std::string> pending{std::string(child)};
    std::set<std::string, std::less<>> visited;
    while (!pending.empty()) {
        auto current = std::move(pending.back());
        pending.pop_back();
        if (current == parent) return true;
        if (!visited.insert(current).second) continue;
        const auto* definition = FindClass(current);
        if (definition == nullptr) continue;
        if (!definition->superclass.empty()) pending.push_back(definition->superclass);
        pending.insert(pending.end(), definition->interfaces.begin(), definition->interfaces.end());
    }
    return false;
}

} // namespace birch::dex
