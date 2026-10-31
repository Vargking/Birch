#include "birch/dex/builder.h"
#include "birch/dex/linkage_verifier.h"
#include "../src/birch/guard/rename_planner.h"

#include <cassert>
#include <iostream>
#include <stdexcept>

namespace {

using namespace birch::dex;
using birch::guard::detail::GlobalRenamePlan;
using birch::guard::detail::RenamePlanner;

DexFile Framework() {
    DexBuilder builder;
    ClassSpec object;
    object.descriptor = "Ljava/lang/Object;";
    object.access_flags = 1U;
    object.superclass.reset();
    builder.AddClass(std::move(object));
    return DexFile::Parse(builder.Build());
}

DexFile Parents() {
    DexBuilder builder;
    ClassSpec parent;
    parent.descriptor = "Lapp/Parent;";
    parent.access_flags = 1U;
    parent.direct_methods.push_back({"staticAlpha", "V", {}, 9U, {0U, 0U, 0U, {0x000eU}}});
    parent.direct_methods.push_back({"privateAlpha", "V", {}, 2U, {1U, 1U, 0U, {0x000eU}}});
    parent.virtual_methods.push_back({"normalAlpha", "V", {}, 1U, {1U, 1U, 0U, {0x000eU}}});
    parent.virtual_methods.push_back({"finalAlpha", "V", {}, 0x11U, {1U, 1U, 0U, {0x000eU}}});
    parent.static_fields.push_back({"ancestorField", "I", 9U});
    builder.AddClass(std::move(parent));
    ClassSpec left;
    left.descriptor = "Lapp/Left;";
    left.access_flags = 0x0601U;
    left.virtual_methods.push_back({"leftBranch", "I", {}, 0x0401U, {}});
    builder.AddClass(std::move(left));
    return DexFile::Parse(builder.Build());
}

DexFile Children(bool shadows_field = false) {
    DexBuilder builder;
    ClassSpec child;
    child.descriptor = "Lapp/Child;";
    child.access_flags = 1U;
    child.superclass = "Lapp/Parent;";
    child.virtual_methods.push_back({"instanceBeta", "V", {}, 1U, {1U, 1U, 0U, {0x000eU}}});
    child.static_fields.push_back({"descendantField", "I", 9U});
    if (shadows_field) child.static_fields.push_back({"ancestorField", "I", 9U});
    MethodSpec reader{"read", "V", {}, 9U, {1U, 0U, 0U, {0x0060U, 0U, 0x000eU}}};
    reader.body.references = {{FieldReference{"Lapp/Child;", "ancestorField", "I"}, 1U}};
    child.direct_methods.push_back(std::move(reader));
    builder.AddClass(std::move(child));
    ClassSpec right;
    right.descriptor = "Lapp/Right;";
    right.access_flags = 0x0601U;
    right.virtual_methods.push_back({"rightBranch", "I", {}, 0x0401U, {}});
    builder.AddClass(std::move(right));
    ClassSpec combined;
    combined.descriptor = "Lapp/Combined;";
    combined.access_flags = 0x0601U;
    combined.interfaces = {"Lapp/Left;", "Lapp/Right;"};
    builder.AddClass(std::move(combined));
    return DexFile::Parse(builder.Build());
}

void CheckPlan(const std::vector<std::reference_wrapper<const DexFile>>& files,
    const DexFile& framework, const birch::guard::ScopeConfig& scope,
    const birch::guard::RenameConfig& config, const GlobalRenamePlan& plan) {
    const auto baseline = LinkageVerifier::Analyze(files, &framework,
        {plan.classes, plan.methods, plan.fields});
    assert(baseline.failures.empty());
    std::vector<DexFile> result;
    for (const auto file : files) {
        result.push_back(DexFile::Parse(RenamePlanner::RenameDex(file.get(), scope,
            config, 11U, true, true, true, &plan).bytes));
    }
    const std::vector<std::reference_wrapper<const DexFile>> refs{result.begin(), result.end()};
    LinkageVerifier::VerifyNoNewFailures(baseline, refs, &framework);
}

void PackageBoundaries(const DexFile& framework, const birch::guard::RenameConfig& config) {
    DexBuilder builder;
    for (const bool same_package : {false, true}) {
        ClassSpec parent;
        parent.descriptor = same_package ? "Lapp/p/Root;" : "Lapp/p/Base;";
        parent.access_flags = 1U;
        parent.virtual_methods.push_back({"packageContract", "V", {}, 0U, {1U, 1U, 0U, {0x000eU}}});
        ClassSpec child;
        child.descriptor = same_package ? "Lapp/p/Leaf;" : "Lapp/q/Derived;";
        child.superclass = parent.descriptor;
        child.virtual_methods.push_back({"packageContract", "V", {}, 1U, {1U, 1U, 0U, {0x000eU}}});
        builder.AddClass(std::move(parent));
        builder.AddClass(std::move(child));
    }
    const auto source = DexFile::Parse(builder.Build());
    birch::guard::ScopeConfig scope;
    scope.protect.push_back({"Lapp/**;"});
    scope.keep.push_back({"Lapp/p/Root;"});
    const auto plan = RenamePlanner::BuildGlobalRenamePlan({source}, scope, config, 11U,
        true, true, true, true, 1.0, &framework);
    assert(plan.classes.at("Lapp/p/Base;").starts_with("Lapp/p/"));
    assert(plan.classes.at("Lapp/q/Derived;").starts_with("Lapp/q/"));
    assert(plan.classes.at("Lapp/p/Leaf;").starts_with("Lapp/p/"));
    CheckPlan({source}, framework, scope, config, plan);
    auto broken = plan;
    broken.classes["Lapp/p/Base;"] = "Lb/Base;";
    broken.classes["Lapp/q/Derived;"] = "Lb/Derived;";
    bool rejected = false;
    try { CheckPlan({source}, framework, scope, config, broken); }
    catch (const std::runtime_error& error) {
        rejected = std::string(error.what()).find("introduced method inheritance") != std::string::npos;
    }
    assert(rejected);
    broken = plan;
    broken.classes["Lapp/p/Leaf;"] = "Lb/Leaf;";
    rejected = false;
    try { CheckPlan({source}, framework, scope, config, broken); }
    catch (const std::runtime_error& error) {
        rejected = std::string(error.what()).find("lost method inheritance") != std::string::npos;
    }
    assert(rejected);
}

void AliasOnlyRename(const birch::guard::RenameConfig& config) {
    DexBuilder builder;
    builder.AddString("alreadyUsed");
    ClassSpec type;
    type.descriptor = "Lapp/AliasOnly;";
    type.direct_methods.push_back({"sourceName", "V", {}, 9U, {0U, 0U, 0U, {0x000eU}}});
    builder.AddClass(std::move(type));
    const auto source = DexFile::Parse(builder.Build());
    birch::guard::ScopeConfig scope;
    scope.protect.push_back({"Lapp/**;"});
    GlobalRenamePlan plan;
    plan.methods["sourceName"] = "alreadyUsed";
    const auto output = DexFile::Parse(RenamePlanner::RenameDex(source, scope, config,
        11U, false, true, false, &plan).bytes);
    assert(output.methods().size() == 1U);
    assert(output.string(output.methods()[0].name_idx) == "alreadyUsed");
}

} // namespace

int main() {
    const auto framework = Framework();
    const auto parents = Parents();
    const auto children = Children();
    const std::vector<std::reference_wrapper<const DexFile>> files{parents, children};
    birch::guard::ScopeConfig scope;
    scope.protect.push_back({"Lapp/**;"});
    birch::guard::RenameConfig config;
    config.dictionary = "abcdefghijklmnopqrstuvwxyz";
    const auto plan = RenamePlanner::BuildGlobalRenamePlan(files, scope, config, 11U,
        true, true, true, true, 1.0, &framework);
    for (const auto* name : {"staticAlpha", "privateAlpha", "normalAlpha", "finalAlpha"}) {
        assert(plan.methods.at(name) != plan.methods.at("instanceBeta"));
    }
    assert(plan.methods.at("leftBranch") != plan.methods.at("rightBranch"));
    CheckPlan(files, framework, scope, config, plan);
    for (const auto* name : {"staticAlpha", "normalAlpha", "finalAlpha"}) {
        auto broken = plan;
        auto& mappings = broken.methods;
        mappings[name] = "collided";
        mappings["instanceBeta"] = "collided";
        bool rejected = false;
        try { CheckPlan(files, framework, scope, config, broken); }
        catch (const std::runtime_error& error) {
            const std::string message = error.what();
            std::cout << "Rejected " << name << ": " << message << std::endl;
            rejected = message.find("mismatch") != std::string::npos ||
                message.find("introduced method inheritance") != std::string::npos ||
                message.find("override of final") != std::string::npos ||
                message.find("changed declaring class") != std::string::npos;
        }
        if (!rejected) std::cerr << "Gate did not reject collision for " << name << std::endl;
        assert(rejected);
    }
    const auto shadowing = Children(true);
    bool binding_rejected = false;
    try {
        LinkageVerifier::VerifyNoNewFailures(LinkageVerifier::Analyze(files, &framework),
            {parents, shadowing}, &framework);
    } catch (const std::runtime_error& error) {
        binding_rejected = std::string(error.what()).find("changed declaring class") != std::string::npos;
    }
    assert(binding_rejected);
    PackageBoundaries(framework, config);
    AliasOnlyRename(config);
    std::cout << "cross-DEX static/private/virtual conflicts, interface branches, binding identity, "
                 "package override boundaries and alias-only renaming passed\n";
}
