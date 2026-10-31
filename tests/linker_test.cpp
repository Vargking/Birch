#include "birch/dex/builder.h"
#include "birch/dex/linker.h"
#include "birch/dex/linkage_verifier.h"
#include "../src/birch/guard/rename_planner.h"

#include <cassert>
#include <iostream>

using birch::dex::ClassSpec;
using birch::dex::DexBuilder;
using birch::dex::DexFile;
using birch::dex::DexLinker;
using birch::dex::ResolutionStatus;

namespace {

DexFile Framework() {
    DexBuilder builder;
    ClassSpec object;
    object.descriptor = "Ljava/lang/Object;";
    object.superclass.reset();
    builder.AddClass(std::move(object));
    ClassSpec activity;
    activity.descriptor = "Landroid/app/Activity;";
    activity.access_flags = 1U;
    activity.virtual_methods.push_back({"setContentView", "V", {"I"}, 1U,
                                       {2U, 2U, 0U, {0x000eU}}});
    activity.direct_methods.push_back({"externalStatic", "V", {}, 9U,
                                      {0U, 0U, 0U, {0x000eU}}});
    activity.instance_fields.push_back({"externalField", "I", 1U});
    activity.static_fields.push_back({"externalConstant", "I", 9U});
    builder.AddClass(std::move(activity));
    ClassSpec contract;
    contract.descriptor = "Landroid/Contract;";
    contract.access_flags = 0x0601U;
    contract.virtual_methods.push_back({"externalInterface", "V", {}, 0x0401U, {}});
    contract.static_fields.push_back({"interfaceConstant", "I", 0x0019U});
    builder.AddClass(std::move(contract));
    return DexFile::Parse(builder.Build());
}

DexFile Child(bool bad_static_invoke = false) {
    DexBuilder builder;
    ClassSpec child;
    child.descriptor = "Lapp/Screen;";
    child.superclass = "Landroid/app/Activity;";
    child.interfaces = {"Lapp/Contract;"};
    birch::dex::MethodSpec caller{"localHelper", "V", {}, 9U,
        {2U, 0U, 2U, {0x0012U, 0x0112U, 0x206eU, 0U, 0x0010U,
                       0x0071U, 0U, 0U, 0x2052U, 0U,
                       0x0060U, 0U, 0x0060U, 0U, 0x106eU, 0U, 0U,
                       0x1072U, 0U, 0U, 0x000eU}}};
    caller.body.invoke_references = {
        {{"Lapp/Screen;", "setContentView", "V", {"I"}}, 3U},
        {{"Lapp/Screen;", "externalStatic", "V", {}}, 6U},
        {{"Lapp/Screen;", "inheritedLocal", "V", {}}, 15U},
        {{"Lapp/Contract;", "externalInterface", "V", {}}, 18U}};
    caller.body.references = {
        {birch::dex::FieldReference{"Lapp/Screen;", "externalField", "I"}, 9U},
        {birch::dex::FieldReference{"Lapp/Screen;", "externalConstant", "I"}, 11U},
        {birch::dex::FieldReference{"Lapp/Contract;", "interfaceConstant", "I"}, 13U}};
    if (bad_static_invoke) caller.body.code_units[5] = 0x106eU;
    child.direct_methods.push_back(std::move(caller));
    builder.AddClass(std::move(child));
    ClassSpec contract;
    contract.descriptor = "Lapp/Contract;";
    contract.access_flags = 0x0601U;
    contract.interfaces = {"Landroid/Contract;", "Lapp/Local;"};
    builder.AddClass(std::move(contract));
    return DexFile::Parse(builder.Build());
}

DexFile OtherDex() {
    DexBuilder builder;
    ClassSpec local;
    local.descriptor = "Lapp/Local;";
    local.access_flags = 0x0601U;
    local.virtual_methods.push_back({"inheritedLocal", "V", {}, 0x0401U, {}});
    builder.AddClass(std::move(local));
    return DexFile::Parse(builder.Build());
}

DexFile UnknownDependency(bool runtime) {
    DexBuilder builder;
    ClassSpec type;
    type.descriptor = "Lapp/Added;";
    if (runtime) {
        birch::dex::MethodSpec call{"call", "V", {}, 9U,
            {0U, 0U, 0U, {0x0071U, 0U, 0U, 0x000eU}}};
        call.body.invoke_reference = {"Lmissing/Api;", "call", "V", {}};
        type.direct_methods.push_back(std::move(call));
    } else {
        type.annotations.push_back({0U, {"Lmissing/Annotation;", {}}});
    }
    builder.AddClass(std::move(type));
    return DexFile::Parse(builder.Build());
}

} // namespace

int main() {
    const auto framework = Framework();
    const auto child = Child();
    const auto other = OtherDex();
    const std::vector<std::reference_wrapper<const DexFile>> files{child, other};
    const DexLinker linker(files, &framework);
    const auto method = linker.ResolveMethod("Lapp/Screen;", "setContentView", "(I)V");
    assert(method.status == ResolutionStatus::Found && method.external);
    assert(method.declaring_class == "Landroid/app/Activity;");
    assert(linker.ResolveMethod("Lapp/Screen;", "externalStatic", "()V").external);
    assert(linker.ResolveMethod("Lapp/Contract;", "externalInterface", "()V").external);
    assert(linker.ResolveMethod("Lapp/Screen;", "inheritedLocal", "()V").declaring_class == "Lapp/Local;");
    assert(linker.ResolveMethod("Lapp/Screen;", "setContentView", "()V").status == ResolutionStatus::Missing);
    assert(linker.ResolveMethod("Lapp/Screen;", "<init>", "()V").status == ResolutionStatus::Missing);
    assert(linker.ResolveField("Lapp/Screen;", "externalField", "I").external);
    assert(linker.ResolveField("Lapp/Screen;", "externalConstant", "I").external);
    assert(linker.ResolveField("Lapp/Contract;", "interfaceConstant", "I").external);
    assert(linker.ResolveField("Lapp/Screen;", "externalField", "J").status == ResolutionStatus::Missing);

    birch::guard::ScopeConfig scope;
    scope.protect.push_back({"Lapp/**;"});
    birch::guard::RenameConfig rename;
    rename.dictionary = "abcdefghijklmnopqrstuvwxyz";
    const auto plan = birch::guard::detail::RenamePlanner::BuildGlobalRenamePlan(
        files, scope, rename, 7U, true, true, true, true, 1.0, &framework);
    for (const auto* name : {"setContentView", "externalStatic", "externalInterface"}) {
        assert(!plan.methods.contains(name));
    }
    for (const auto* name : {"externalField", "externalConstant", "interfaceConstant"}) {
        assert(!plan.fields.contains(name));
    }
    assert(plan.methods.contains("inheritedLocal"));
    assert(plan.methods.contains("localHelper"));
    assert(plan.classes.contains("Lapp/Screen;"));
    const birch::dex::LinkageRenames renames{plan.classes, plan.methods, plan.fields};
    const auto baseline = birch::dex::LinkageVerifier::Analyze(files, &framework, renames);
    assert(baseline.failures.empty());
    std::vector<DexFile> renamed;
    for (const auto file : files) {
        renamed.push_back(DexFile::Parse(birch::guard::detail::RenamePlanner::RenameDex(
            file.get(), scope, rename, 7U, true, true, true, &plan).bytes));
    }
    birch::dex::LinkageVerifier::VerifyNoNewFailures(baseline, {renamed[0], renamed[1]}, &framework);
    for (const auto field_bug : {false, true}) {
        auto broken = plan;
        if (field_bug) broken.fields["externalField"] = "brokenField";
        else broken.methods["setContentView"] = "brokenMethod";
        const auto bad = DexFile::Parse(birch::guard::detail::RenamePlanner::RenameDex(
            child, scope, rename, 7U, true, true, true, &broken).bytes);
        const auto translated = birch::dex::LinkageVerifier::Analyze(files, &framework,
            {broken.classes, broken.methods, broken.fields});
        bool rejected = false;
        try { birch::dex::LinkageVerifier::VerifyNoNewFailures(translated, {bad, renamed[1]}, &framework); }
        catch (const std::runtime_error& error) {
            rejected = std::string(error.what()).find("missing ") != std::string::npos;
        }
        assert(rejected);
    }
    const auto original = birch::dex::LinkageVerifier::Analyze(files, &framework);
    const auto bad_opcode = Child(true);
    bool opcode_rejected = false;
    try { birch::dex::LinkageVerifier::VerifyNoNewFailures(original, {bad_opcode, other}, &framework); }
    catch (const std::runtime_error& error) {
        opcode_rejected = std::string(error.what()).find("static/instance mismatch") != std::string::npos;
    }
    assert(opcode_rejected);
    const auto annotation_only = UnknownDependency(false);
    const auto metadata_report = birch::dex::LinkageVerifier::Analyze({annotation_only}, &framework);
    assert(!metadata_report.unresolved.empty() && metadata_report.runtime_unresolved.empty());
    birch::dex::LinkageVerifier::VerifyNoNewFailures(original, {child, other, annotation_only}, &framework);
    const auto unknown_runtime = UnknownDependency(true);
    const auto unknown_report = birch::dex::LinkageVerifier::Analyze({unknown_runtime}, &framework);
    assert(!unknown_report.runtime_unresolved.empty());
    // Original optional dependencies are distinct from newly injected calls.
    birch::dex::LinkageVerifier::VerifyNoNewFailures(unknown_report, {unknown_runtime}, &framework);
    bool unknown_rejected = false;
    try { birch::dex::LinkageVerifier::VerifyNoNewFailures(original, {child, other, unknown_runtime}, &framework); }
    catch (const std::runtime_error& error) {
        unknown_rejected = std::string(error.what()).find("introduced unresolved executable reference") != std::string::npos;
    }
    assert(unknown_rejected);

    const auto without_framework = birch::guard::detail::RenamePlanner::BuildGlobalRenamePlan(
        files, scope, rename, 7U, true, true, true, true, 1.0);
    assert(!without_framework.methods.contains("setContentView"));
    assert(!without_framework.fields.contains("externalField"));
    assert(without_framework.methods.contains("localHelper"));
    bool duplicate_rejected = false;
    try { const DexLinker duplicate({child, child}); }
    catch (const std::runtime_error&) { duplicate_rejected = true; }
    assert(duplicate_rejected);
    std::cout << "inherited methods/fields, interfaces, cross-DEX and safe renaming passed\n";
}
