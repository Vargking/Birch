#include "package_access.h"

#include "birch/dex/code.h"

namespace birch::guard::detail {
namespace {

std::string Prefix(std::string_view owner) {
    const auto slash = owner.rfind('/');
    return slash == std::string_view::npos ? "L" : std::string(owner.substr(0, slash + 1U));
}

} // namespace

std::map<std::string, std::string, std::less<>> PackageAccessPlanner::RequiredPrefixes(
    const std::vector<std::reference_wrapper<const dex::DexFile>>& files,
    const dex::DexFile* framework,
    const std::set<std::string, std::less<>>& renamed_classes) {
    const dex::DexLinker linker(files, framework);
    std::map<std::string, std::set<std::string, std::less<>>, std::less<>> neighbors;
    std::set<std::string, std::less<>> preserve_package;
    const auto connect = [&](const std::string& caller, const std::string& owner) {
        if (caller == owner || Prefix(caller) != Prefix(owner)) return;
        neighbors[caller].insert(owner);
        neighbors[owner].insert(caller);
    };
    const auto type_access = [&](const std::string& caller, std::string type) {
        while (type.starts_with('[')) type.erase(0U, 1U);
        const auto* definition = linker.FindClass(type);
        if (definition != nullptr && (definition->access_flags & 1U) == 0U) connect(caller, type);
    };
    const auto signature = [&](const std::string& caller, std::string_view proto) {
        for (auto start = proto.find('L'); start != std::string_view::npos;) {
            const auto end = proto.find(';', start);
            if (end == std::string_view::npos) break;
            type_access(caller, std::string(proto.substr(start, end + 1U - start)));
            start = proto.find('L', end + 1U);
        }
    };
    const auto member_access = [&](const std::string& caller, const dex::MemberResolution& target) {
        if (target.status == dex::ResolutionStatus::Found &&
            (target.access_flags & (1U | 2U)) == 0U) connect(caller, target.declaring_class);
    };
    for (const auto file : files) {
        const auto& dex_file = file.get();
        for (std::size_t index = 0; index < dex_file.classes().size(); ++index) {
            const auto& klass = dex_file.classes()[index];
            const auto caller = dex_file.descriptor(klass.class_idx);
            const auto* child = linker.FindClass(caller);
            std::vector<std::string> ancestors = child->interfaces;
            if (!child->superclass.empty()) ancestors.push_back(child->superclass);
            std::set<std::string, std::less<>> visited_ancestors;
            while (!ancestors.empty()) {
                auto ancestor = std::move(ancestors.back());
                ancestors.pop_back();
                if (!visited_ancestors.insert(ancestor).second) continue;
                const auto* parent = linker.FindClass(ancestor);
                if (parent == nullptr) continue;
                if (!parent->superclass.empty()) ancestors.push_back(parent->superclass);
                ancestors.insert(ancestors.end(), parent->interfaces.begin(), parent->interfaces.end());
                for (const auto& [signature_key, method] : child->methods) {
                    if (signature_key.starts_with('<') || !method.virtual_method) continue;
                    const auto inherited = parent->methods.find(signature_key);
                    if (inherited == parent->methods.end() || !inherited->second.virtual_method ||
                        (inherited->second.access_flags & (1U | 2U | 4U)) != 0U) continue;
                    if (Prefix(caller) == Prefix(ancestor)) {
                        // An override remains an override even when no direct
                        // invoke instruction mentions the parent declaration.
                        connect(caller, ancestor);
                    } else {
                        // Flattening different packages would create a NEW
                        // override for an originally inaccessible method.
                        preserve_package.insert(caller);
                        preserve_package.insert(ancestor);
                        neighbors[caller];
                        neighbors[ancestor];
                    }
                }
            }
            if (klass.superclass_idx != 0xffffffffU) type_access(caller, dex_file.descriptor(klass.superclass_idx));
            for (const auto type : dex_file.type_list(klass.interfaces_off)) type_access(caller, dex_file.descriptor(type));
            const auto& data = dex_file.class_data(index);
            for (const auto* fields : {&data.static_fields, &data.instance_fields}) {
                for (const auto& encoded : *fields) {
                    type_access(caller, dex_file.descriptor(dex_file.fields().at(encoded.field_idx).type_idx));
                }
            }
            for (const auto* methods : {&data.direct_methods, &data.virtual_methods}) {
                for (const auto& encoded : *methods) {
                    signature(caller, dex_file.proto_key(dex_file.methods().at(encoded.method_idx).proto_idx));
                    if (encoded.code_off == 0U) continue;
                    for (const auto& insn : dex::DecodeCodeItem(dex_file, encoded.code_off).instructions) {
                        const auto op = insn.opcode;
                        if ((op >= 0x6eU && op <= 0x72U) || (op >= 0x74U && op <= 0x78U)) {
                            const auto& ref = dex_file.methods().at(insn.code_units.at(1));
                            const auto owner = dex_file.descriptor(ref.class_idx);
                            type_access(caller, owner);
                            member_access(caller, linker.ResolveMethod(owner, dex_file.string(ref.name_idx), dex_file.proto_key(ref.proto_idx)));
                        } else if (op >= 0x52U && op <= 0x6dU) {
                            const auto& ref = dex_file.fields().at(insn.code_units.at(1));
                            const auto owner = dex_file.descriptor(ref.class_idx);
                            type_access(caller, owner);
                            member_access(caller, linker.ResolveField(owner, dex_file.string(ref.name_idx), dex_file.descriptor(ref.type_idx)));
                        } else if (op == 0x1cU || op == 0x1fU || op == 0x20U ||
                                   (op >= 0x22U && op <= 0x25U)) {
                            type_access(caller, dex_file.descriptor(insn.code_units.at(1)));
                        }
                    }
                }
            }
        }
    }
    std::map<std::string, std::string, std::less<>> result;
    std::set<std::string, std::less<>> visited;
    for (const auto& [root, edges] : neighbors) {
        (void)edges;
        if (visited.contains(root)) continue;
        std::vector<std::string> pending{root};
        std::vector<std::string> component;
        bool pinned = false;
        while (!pending.empty()) {
            auto owner = std::move(pending.back());
            pending.pop_back();
            if (!visited.insert(owner).second) continue;
            component.push_back(owner);
            pinned = pinned || !renamed_classes.contains(owner) || preserve_package.contains(owner);
            const auto& next = neighbors.at(owner);
            pending.insert(pending.end(), next.begin(), next.end());
        }
        if (pinned) for (const auto& owner : component) {
            if (renamed_classes.contains(owner)) result.emplace(owner, Prefix(owner));
        }
    }
    return result;
}

} // namespace birch::guard::detail
