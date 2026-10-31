#include "inheritance_verifier.h"

#include "linkage_names.h"

#include <utility>

namespace birch::dex::detail {

void InheritanceVerifier::Analyze(const DexLinker& linker,
    const std::vector<std::reference_wrapper<const DexFile>>& files,
    const LinkageRenames& renames, LinkageReport& report) {
    for (const auto file : files) {
        const auto& dex = file.get();
        for (const auto& definition : dex.classes()) {
            const auto owner = dex.descriptor(definition.class_idx);
            const auto translated_owner = Translate(owner, renames.classes);
            report.application_classes.insert(translated_owner);
            const auto* child = linker.FindClass(owner);
            std::vector<std::string> pending = child->interfaces;
            if (!child->superclass.empty()) pending.push_back(child->superclass);
            std::set<std::string, std::less<>> visited;
            while (!pending.empty()) {
                auto ancestor = std::move(pending.back());
                pending.pop_back();
                if (!visited.insert(ancestor).second) continue;
                const auto* parent = linker.FindClass(ancestor);
                if (parent == nullptr) continue;
                if (!parent->superclass.empty()) pending.push_back(parent->superclass);
                pending.insert(pending.end(), parent->interfaces.begin(), parent->interfaces.end());
                for (const auto& [signature, method] : child->methods) {
                    if (signature.starts_with('<') || (method.access_flags & 2U) != 0U) continue;
                    const auto inherited = parent->methods.find(signature);
                    if (inherited == parent->methods.end()) continue;
                    const auto& target = inherited->second;
                    if ((target.access_flags & 2U) != 0U) continue;
                    if ((parent->access_flags & 0x0200U) != 0U &&
                        (target.access_flags & 8U) != 0U) continue;
                    if ((target.access_flags & (1U | 4U)) == 0U &&
                        Package(owner) != Package(ancestor)) continue;
                    const auto proto = signature.find('(');
                    const auto translated_signature = Rename(signature.substr(0, proto), renames.methods) +
                        Translate(std::string_view(signature).substr(proto), renames.classes);
                    const auto translated_parent = Translate(ancestor, renames.classes);
                    report.inheritance.emplace(translated_owner, translated_parent, translated_signature);
                    const auto key = translated_owner + "->" + translated_signature + " over " + translated_parent;
                    if (((method.access_flags ^ target.access_flags) & 8U) != 0U) {
                        report.failures.insert("inherited static/instance mismatch " + key);
                    } else if ((method.access_flags & 8U) == 0U &&
                               (target.access_flags & 0x10U) != 0U) {
                        report.failures.insert("override of final method " + key);
                    }
                }
            }
        }
    }
}

} // namespace birch::dex::detail
