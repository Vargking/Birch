#include "../src/birch/guard/apk_dex_layout.h"

#include "birch/dex/builder.h"
#include "birch/dex/verifier.h"
#include "birch/guard/apk.h"
#include "birch/guard/axml.h"
#include "birch/io/apk_entries.h"
#include "support/synthetic_apk.h"

#include <cassert>
#include <filesystem>
#include <functional>
#include <iostream>

namespace {

using birch::guard::ZipArchive;
using birch::guard::ZipCompression;
using birch::guard::detail::ApkDexLayout;

std::uint32_t U32(const std::vector<std::uint8_t>& bytes, std::size_t at) {
    assert(at + 4U <= bytes.size());
    std::uint32_t value = 0U;
    for (unsigned i = 0U; i < 4U; ++i) value |= static_cast<std::uint32_t>(bytes[at + i]) << (8U * i);
    return value;
}

std::vector<std::uint8_t> Manifest(unsigned api) {
    auto bytes = birch::test::MinimalManifest();
    const auto document = birch::guard::AxmlDocument::Parse(bytes);
    for (const auto& chunk : document.chunks()) {
        if (chunk.type != 0x0102U) continue;
        const auto ext = static_cast<std::size_t>(chunk.offset) + chunk.header_size;
        if (document.strings().at(U32(bytes, ext + 4U)) != "uses-sdk") continue;
        const auto start = U32(bytes, ext + 8U) & 0xffffU;
        const auto stride = U32(bytes, ext + 8U) >> 16U;
        const auto count = U32(bytes, ext + 12U) & 0xffffU;
        for (unsigned i = 0U; i < count; ++i) {
            const auto at = ext + start + i * stride;
            if (document.strings().at(U32(bytes, at + 4U)) != "minSdkVersion") continue;
            assert(bytes[at + 15U] == 0x10U);
            for (unsigned j = 0U; j < 4U; ++j) bytes[at + 16U + j] = static_cast<std::uint8_t>(api >> (8U * j));
            return bytes;
        }
    }
    throw std::runtime_error("test input has no numeric minSdkVersion");
}

std::vector<std::uint8_t> Dex(std::string owner, std::string dependency = {}) {
    birch::dex::DexBuilder builder;
    birch::dex::ClassSpec type;
    type.descriptor = std::move(owner);
    type.direct_methods.push_back({"run", "V", {}, 9U, {0U, 0U, 0U, {0x000eU}}});
    if (!dependency.empty()) type.static_fields.push_back({"peer", std::move(dependency), 9U});
    builder.AddClass(std::move(type));
    return builder.Build();
}

ZipArchive Archive(unsigned api, const std::vector<std::uint8_t>& primary) {
    ZipArchive result;
    result.Add({"AndroidManifest.xml", Manifest(api), ZipCompression::Stored});
    result.Add({"classes.dex", primary, ZipCompression::Stored});
    return result;
}

void Reject(const std::function<void()>& action, std::string_view message) {
    bool rejected = false;
    try { action(); }
    catch (const std::exception& error) {
        rejected = true;
        assert(std::string_view(error.what()).find(message) != std::string_view::npos);
    }
    assert(rejected);
}

} // namespace

int main() {
    const auto main = Dex("Lapp/Main;");
    const auto extra = Dex("Lfake/Extra;", "Lapp/Main;");
    const auto source = Archive(19U, main);
    const ApkDexLayout legacy(source);
    assert(legacy.min_sdk() == 19U);
    auto output = source;
    output.Add({"classes2.dex", extra, ZipCompression::Stored});
    Reject([&] { legacy.Verify(output, {}); }, "single-DEX");
    auto limits = birch::dex::IdLimits{};
    limits.types = 1U;
    Reject([&] { (void)legacy.MergeGeneratedDex(output, "classes2.dex", limits); }, "ID limits");
    assert(output.Find("classes.dex")->data == main);
    assert(output.Find("classes2.dex")->data == extra);
    assert(legacy.MergeGeneratedDex(output, "classes2.dex", {}));
    assert(output.Find("classes2.dex") == nullptr);
    const auto merged = birch::dex::DexFile::Parse(output.Find("classes.dex")->data);
    assert(merged.classes().size() == 2U);
    assert(birch::dex::VerifyDex(merged, birch::dex::VerificationLevel::Full).ok);
    legacy.Verify(output, {});

    const auto native_source = Archive(21U, main);
    const ApkDexLayout native(native_source);
    auto native_output = native_source;
    native_output.Add({"classes2.dex", extra, ZipCompression::Stored});
    native.Verify(native_output, {});
    Reject([&] { legacy.Verify(native_output, {}); }, "minSdkVersion");

    auto multi_source = source;
    multi_source.Add({"classes2.dex", extra, ZipCompression::Stored});
    const ApkDexLayout multi(multi_source);
    multi.Verify(multi_source, {});
    auto moved = Archive(19U, Dex("Lother/Type;"));
    moved.Add({"classes2.dex", Dex("Lb/Renamed;"), ZipCompression::Stored});
    Reject([&] { multi.Verify(moved, {{"Lapp/Main;", "Lb/Renamed;"}}); }, "moved out of primary");

    auto dependency = Archive(19U, Dex("Lapp/Main;", "[[Lfake/Extra;"));
    dependency.Add({"classes2.dex", extra, ZipCompression::Stored});
    Reject([&] { multi.Verify(dependency, {}); }, "primary-to-secondary");
    // Existing, possibly post-install secondary references are not a new error.
    const ApkDexLayout baseline(dependency);
    baseline.Verify(dependency, {});
    const ApkDexLayout native_multi(native_output);
    assert(!native_multi.MergeGeneratedDex(native_output, "classes2.dex", {}));

    auto secondary_only = source;
    assert(secondary_only.RemoveEntry("classes.dex"));
    secondary_only.Add({"classes2.dex", main, ZipCompression::Stored});
    Reject([&] { (void)ApkDexLayout(secondary_only); }, "primary classes.dex");
    secondary_only.Add({"resources.arsc", birch::test::EmptyResources(), ZipCompression::Stored});
    Reject([&] { (void)birch::guard::InspectApk(secondary_only); }, "primary classes.dex");

    // Every candidate must be validated even when sort never invokes its
    // comparator (a one-entry archive), and secondary names must be canonical.
    assert(birch::io::DexEntryOrdinal("classes.dex") == 1U);
    assert(birch::io::DexEntryOrdinal("classes2.dex") == 2U);
    assert(birch::io::DexEntryOrdinal("classes4294967295.dex") == 4294967295U);
    for (const auto name : {"classes0.dex", "classes1.dex", "classes02.dex",
                            "classes0002.dex", "classes4294967296.dex"}) {
        Reject([&] { (void)birch::io::DexEntryOrdinal(name); }, "DEX");
        ZipArchive invalid;
        invalid.Add({name, main, ZipCompression::Stored});
        Reject([&] { (void)birch::io::DexEntryNames(invalid); }, "DEX");
    }
    auto order = source;
    order.Add({"classes10.dex", extra, ZipCompression::Stored});
    order.Add({"classes2.dex", extra, ZipCompression::Stored});
    assert((birch::io::DexEntryNames(order) ==
        std::vector<std::string>{"classes.dex", "classes2.dex", "classes10.dex"}));
    assert(birch::io::NextDexEntryName(order) == "classes11.dex");
    std::cout << "APK SDK, primary placement, new dependency, exact merge and fail-closed ID tests passed\n";
}
