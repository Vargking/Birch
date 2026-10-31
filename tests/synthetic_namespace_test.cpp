#include "birch/dex/builder.h"
#include "birch/dex/linker.h"
#include "birch/dex/verifier.h"
#include "birch/guard/model_lowering.h"
#include "birch/guard/pipeline.h"
#include "birch/io/file.h"
#include "model_strings.h"
#include "model_support.h"
#include "class_namespace.h"
#include "support/synthetic_apk.h"

#include <cassert>
#include <filesystem>
#include <iostream>
#include <set>

namespace {
using Names = std::set<std::string, std::less<>>;

birch::dex::DexFile Source(std::string owner, std::string referenced = {}) {
    using namespace birch::dex;
    ClassSpec klass;
    klass.descriptor = std::move(owner);
    MethodSpec method;
    method.name = "read";
    method.return_type = "Ljava/lang/String;";
    method.body.registers_size = 1U;
    method.body.code_units = {0x001aU, 0U, 0x0011U};
    method.body.references = {{std::string("namespace-regression"), 1U, false}};
    klass.direct_methods.push_back(std::move(method));
    if (!referenced.empty()) klass.static_fields.push_back({"peer", "[[" + referenced, 9U});
    DexBuilder builder;
    builder.AddClass(std::move(klass));
    return DexFile::Parse(builder.Build());
}

birch::guard::GuardConfig Config() {
    auto config = birch::guard::GuardConfig::Defaults();
    for (auto& [id, pass] : config.passes) {
        (void)id;
        pass.enabled = false;
        pass.intensity = 1.0;
    }
    config.scope.protect = {{"Lnamespace/**;"}};
    config.scope.keep.clear();
    config.passes.at("data.string_encryption").enabled = true;
    config.passes.at("rename.classes").enabled = true;
    config.strength.reproducible_output = true;
    // Two minimal input classes are smaller than a single encrypted vault.
    config.budget.max_dex_growth_ratio = 16.0;
    config.output.write_mapping = false;
    return config;
}

Names Generated(const birch::dex::DexFile& output, std::string_view owner) {
    Names result;
    for (const auto& klass : output.classes()) {
        const auto name = output.descriptor(klass.class_idx);
        if (name != owner) result.insert(name);
    }
    return result;
}

void CheckHighSeedBits() {
    using namespace birch;
    Names names;
    const Names values{"namespace-regression"};
    const auto first = guard::detail::ModelStringProtection::BuildStringHelper(
        names, values, {}, 7U, 19U);
    const auto second = guard::detail::ModelStringProtection::BuildStringHelper(
        names, values, {}, 7ULL + (1ULL << 32U), 19U);
    // The old two truncated FNV hashes ignored every high seed bit. This is a
    // deterministic reproducer, not a probabilistic birthday-collision test.
    assert(first.entry_descriptor != second.entry_descriptor);
    dex::DexBuilder left, right;
    for (const auto& klass : first.classes) left.AddClass(klass);
    for (const auto& klass : second.classes) right.AddClass(klass);
    const auto dex1 = dex::DexFile::Parse(left.Build());
    const auto dex2 = dex::DexFile::Parse(right.Build());
    const dex::DexLinker linker({std::cref(dex1), std::cref(dex2)});
    assert(linker.FindClass(first.entry_descriptor));
    assert(linker.FindClass(second.entry_descriptor));
    assert(guard::detail::SyntheticClassDescriptor("proxy", "Lnamespace/A;", 7U, 0U, {}) !=
           guard::detail::SyntheticClassDescriptor("proxy", "Lnamespace/A;",
                                                   7ULL + (1ULL << 32U), 0U, {}));
}

void CheckReservedDefinitionsAndReferences() {
    using namespace birch;
    const auto config = Config();
    const auto source = Source("Lnamespace/App;");
    const auto ordinary = dex::DexFile::Parse(guard::DexModelLowering(config).Apply(source).bytes);
    const auto generated = Generated(ordinary, "Lnamespace/App;");
    assert(!generated.empty());
    const auto collision = *generated.begin();
    // A real class with the would-be helper name lives in another DEX.
    const auto other = Source(collision);
    guard::detail::ClassNamespace names;
    names.Reserve(source);
    names.Reserve(other);
    const auto protected_dex = dex::DexFile::Parse(
        guard::DexModelLowering(config).Apply(source, names.names()).bytes);
    dex::VerifyDexOrThrow(protected_dex, dex::VerificationLevel::Full);
    const dex::DexLinker linker({std::cref(protected_dex), std::cref(other)});
    assert(linker.FindClass(collision));
    assert(!Generated(protected_dex, "Lnamespace/App;").contains(collision));

    // A name can be reserved only by an array reference, not a definition.
    const auto referencing = Source("Lnamespace/Peer;", collision);
    guard::detail::ClassNamespace references;
    references.Reserve(referencing);
    assert(references.names().contains(collision));
    const auto safe = dex::DexFile::Parse(
        guard::DexModelLowering(config).Apply(source, references.names()).bytes);
    assert(!Generated(safe, "Lnamespace/App;").contains(collision));

    // Exercise the production APK orchestration, not just the lower-level API.
    auto archive = test::ApkWithDex(source.bytes());
    archive.Add({"classes2.dex", {other.bytes().begin(), other.bytes().end()},
                 guard::ZipCompression::Stored});
    const std::filesystem::path input = "synthetic-namespace-source.apk";
    const std::filesystem::path output = "synthetic-namespace-output.apk";
    io::WriteBinaryFile(input, archive.Write());
    guard::GuardPipeline::FromConfig(config).TransformApk(input, output);
    const auto result = guard::ZipArchive::Read(output);
    std::vector<dex::DexFile> files;
    for (const auto& entry : result.entries()) {
        if (!entry.name.ends_with(".dex")) continue;
        files.push_back(dex::DexFile::Parse(entry.data));
        dex::VerifyDexOrThrow(files.back(), dex::VerificationLevel::Full);
    }
    assert(files.size() == 2U);
    const dex::DexLinker output_linker({std::cref(files.at(0)), std::cref(files.at(1))});
    (void)output_linker;
    std::filesystem::remove(input);
    std::filesystem::remove(output);
    std::filesystem::remove(output.string() + ".techniques.txt");
}
} // namespace

int main() {
    CheckHighSeedBits();
    CheckReservedDefinitionsAndReferences();
    std::cout << "Synthetic namespaces retain high seed bits and reserve multi-DEX definitions/references\n";
}
