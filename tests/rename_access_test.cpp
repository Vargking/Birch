#include "birch/dex/builder.h"
#include "birch/dex/linkage_verifier.h"
#include "../src/birch/guard/rename_planner.h"

#include <cassert>
#include <iostream>

namespace {

using birch::dex::ClassSpec;
using birch::dex::DexBuilder;
using birch::dex::DexFile;
using birch::guard::detail::RenamePlanner;

DexFile Source() {
    DexBuilder builder;
    ClassSpec kept;
    kept.descriptor = "Lpkg/Kept;";
    kept.static_fields.push_back({"packageField", "I", 8U});
    kept.direct_methods.push_back({"packageMethod", "V", {}, 8U, {0U, 0U, 0U, {0x000eU}}});
    builder.AddClass(std::move(kept));
    ClassSpec type;
    type.descriptor = "Lpkg/PackageType;";
    type.access_flags = 0x0010U;
    builder.AddClass(std::move(type));
    ClassSpec caller;
    caller.descriptor = "Lpkg/Caller;";
    caller.static_fields.push_back({"one", "[Lpkg/Item;", 9U});
    caller.static_fields.push_back({"two", "[[Lpkg/Item;", 9U});
    caller.static_fields.push_back({"primitive", "[I", 9U});
    birch::dex::MethodSpec access{"access", "V", {}, 8U,
        {1U, 0U, 0U, {0x0060U, 0U, 0x0071U, 0U, 0U, 0x001cU, 0U, 0x000eU}}};
    access.body.invoke_reference = {"Lpkg/Kept;", "packageMethod", "V", {}};
    access.body.invoke_reference_unit = 3U;
    access.body.references = {
        {birch::dex::FieldReference{"Lpkg/Kept;", "packageField", "I"}, 1U},
        {birch::dex::TypeReference{"Lpkg/PackageType;"}, 6U}};
    caller.direct_methods.push_back(std::move(access));
    builder.AddClass(std::move(caller));
    ClassSpec peer;
    peer.descriptor = "Lpkg/Peer;";
    birch::dex::MethodSpec call{"peer", "V", {}, 9U, {0U, 0U, 0U, {0x0071U, 0U, 0U, 0x000eU}}};
    call.body.invoke_reference = {"Lpkg/Caller;", "access", "V", {}};
    peer.direct_methods.push_back(std::move(call));
    builder.AddClass(std::move(peer));
    ClassSpec item;
    item.descriptor = "Lpkg/Item;";
    builder.AddClass(std::move(item));
    return DexFile::Parse(builder.Build());
}

DexFile CrossDex() {
    DexBuilder builder;
    ClassSpec other;
    other.descriptor = "Lclient/Other;";
    other.static_fields.push_back({"items", "[[Lpkg/Item;", 9U});
    other.direct_methods.push_back({"accept", "V", {"[Lpkg/Item;", "[[Lpkg/Item;"}, 9U,
                                    {2U, 2U, 0U, {0x000eU}}});
    builder.AddClass(std::move(other));
    return DexFile::Parse(builder.Build());
}

} // namespace

int main() {
    const auto source = Source();
    const auto cross = CrossDex();
    birch::guard::ScopeConfig scope;
    scope.protect.push_back({"Lpkg/**;"});
    scope.keep.push_back({"Lpkg/Kept;"});
    scope.keep.push_back({"Lpkg/PackageType;"});
    birch::guard::RenameConfig config;
    config.dictionary = "abcdefghijklmnopqrstuvwxyz";
    const std::vector<std::reference_wrapper<const DexFile>> files{source, cross};
    const auto plan = RenamePlanner::BuildGlobalRenamePlan(files, scope, config, 9U,
                                                         true, true, true, true, 1.0);
    assert(plan.classes.at("Lpkg/Caller;").starts_with("Lpkg/"));
    assert(plan.classes.at("Lpkg/Caller;") != "Lpkg/Caller;");
    assert(plan.classes.at("Lpkg/Peer;").starts_with("Lpkg/"));
    assert(plan.classes.at("Lpkg/Item;").starts_with("Lb/"));
    assert(plan.methods.contains("access"));
    const auto baseline = birch::dex::LinkageVerifier::Analyze(files, nullptr,
        {plan.classes, plan.methods, plan.fields});
    assert(baseline.failures.empty());
    std::vector<DexFile> outputs;
    for (const auto file : files) {
        outputs.push_back(DexFile::Parse(RenamePlanner::RenameDex(file.get(), scope, config,
            9U, true, true, true, &plan).bytes));
    }
    birch::dex::LinkageVerifier::VerifyNoNewFailures(baseline, {outputs[0], outputs[1]});
    for (const auto& output : outputs) {
        bool array_found = false;
        for (const auto& type : output.types()) {
            const auto value = output.string(type.descriptor_idx);
            assert(value.find("Lpkg/Item;") == std::string::npos);
            array_found = array_found || value == "[[" + plan.classes.at("Lpkg/Item;");
        }
        assert(array_found);
    }
    auto wrong = plan;
    wrong.classes["Lpkg/Caller;"] = "Lb/Broken;";
    const auto bad = DexFile::Parse(RenamePlanner::RenameDex(source, scope, config,
        9U, true, true, true, &wrong).bytes);
    const auto bad_baseline = birch::dex::LinkageVerifier::Analyze(files, nullptr,
        {wrong.classes, wrong.methods, wrong.fields});
    bool access_rejected = false;
    try { birch::dex::LinkageVerifier::VerifyNoNewFailures(bad_baseline, {bad, outputs[1]}); }
    catch (const std::runtime_error& error) {
        access_rejected = std::string(error.what()).find("inaccessible") != std::string::npos;
    }
    assert(access_rejected);

    // Recreate the former array-component omission without changing the class.
    std::map<std::uint32_t, std::pair<std::string, std::uint32_t>> stale;
    for (std::size_t i = 0; i < outputs[1].strings().size(); ++i) {
        if (outputs[1].string(static_cast<std::uint32_t>(i)) == "[[" + plan.classes.at("Lpkg/Item;")) {
            stale.emplace(static_cast<std::uint32_t>(i), std::make_pair("[[Lpkg/Item;", 12U));
        }
    }
    assert(!stale.empty());
    const auto stale_output = DexFile::Parse(outputs[1].ReplaceStrings(stale));
    bool stale_rejected = false;
    try { birch::dex::LinkageVerifier::VerifyNoNewFailures(baseline, {outputs[0], stale_output}); }
    catch (const std::runtime_error& error) {
        stale_rejected = std::string(error.what()).find("stale renamed type") != std::string::npos;
    }
    assert(stale_rejected);
    std::cout << "package access, transitive constraints and cross-DEX multidimensional arrays passed\n";
}
