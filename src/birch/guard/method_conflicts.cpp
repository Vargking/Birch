#include "method_conflicts.h"

#include <iterator>
#include <utility>

namespace birch::guard::detail {

MethodConflictPlanner::Conflicts MethodConflictPlanner::Build(
    const std::vector<std::reference_wrapper<const dex::DexFile>>& files,
    const dex::DexFile* framework) {
    using ProtoNames = std::map<std::string, std::set<std::string, std::less<>>, std::less<>>;
    std::map<std::string, ProtoNames, std::less<>> names;
    std::map<std::string, std::vector<std::string>, std::less<>> hierarchy;
    const auto add_hierarchy = [&](const dex::DexFile& dex_file, bool external) {
        for (const auto& definition : dex_file.classes()) {
            const auto owner = dex_file.descriptor(definition.class_idx);
            if (external && hierarchy.contains(owner)) continue;
            auto& parents = hierarchy[owner];
            parents.clear();
            if (definition.superclass_idx != 0xffffffffU) {
                parents.push_back(dex_file.descriptor(definition.superclass_idx));
            }
            for (const auto type : dex_file.type_list(definition.interfaces_off)) {
                parents.push_back(dex_file.descriptor(type));
            }
        }
    };
    for (const auto file : files) {
        const auto& dex_file = file.get();
        add_hierarchy(dex_file, false);
        // All ids, not only declarations: cross-DEX inherited references may
        // introduce a second signature under an otherwise empty child owner.
        for (const auto& method : dex_file.methods()) {
            const auto name = dex_file.string(method.name_idx);
            if (name == "<init>" || name == "<clinit>") continue;
            names[dex_file.descriptor(method.class_idx)]
                [dex_file.proto_key(method.proto_idx)].insert(name);
        }
    }
    if (framework != nullptr) add_hierarchy(*framework, true);
    Conflicts result;
    std::set<std::string, std::less<>> owners;
    for (const auto& [owner, parents] : hierarchy) {
        (void)parents;
        owners.insert(owner);
    }
    for (const auto& [owner, methods] : names) {
        (void)methods;
        owners.insert(owner);
    }
    for (const auto& owner : owners) {
        ProtoNames visible;
        std::vector<std::string> pending{owner};
        std::set<std::string, std::less<>> visited;
        while (!pending.empty()) {
            auto current = std::move(pending.back());
            pending.pop_back();
            if (!visited.insert(current).second) continue;
            if (const auto found = names.find(current); found != names.end()) {
                for (const auto& [proto, members] : found->second) {
                    visible[proto].insert(members.begin(), members.end());
                }
            }
            if (const auto found = hierarchy.find(current); found != hierarchy.end()) {
                pending.insert(pending.end(), found->second.begin(), found->second.end());
            }
        }
        for (const auto& [proto, members] : visible) {
            (void)proto;
            for (auto left = members.begin(); left != members.end(); ++left) {
                for (auto right = std::next(left); right != members.end(); ++right) {
                    result[*left].insert(*right);
                    result[*right].insert(*left);
                }
            }
        }
    }
    return result;
}

} // namespace birch::guard::detail
