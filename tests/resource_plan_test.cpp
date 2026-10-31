#include "resource_obfuscator.h"
#include "birch/guard/arsc.h"
#include "birch/dex/builder.h"
#include <algorithm>
#include <cassert>
#include <iostream>

namespace {
using Bytes = std::vector<std::uint8_t>;
void U16(Bytes& bytes, std::size_t at, std::uint16_t value) {
    bytes.at(at) = static_cast<std::uint8_t>(value);
    bytes.at(at + 1U) = static_cast<std::uint8_t>(value >> 8U);
}
void U32(Bytes& bytes, std::size_t at, std::uint32_t value) {
    for (unsigned i = 0; i < 4U; ++i) bytes.at(at + i) = static_cast<std::uint8_t>(value >> (8U * i));
}
Bytes Pool(const std::vector<std::string>& strings) {
    Bytes bytes(28U + 4U * strings.size());
    U16(bytes, 0U, 1U); U16(bytes, 2U, 28U);
    U32(bytes, 8U, static_cast<std::uint32_t>(strings.size())); U32(bytes, 16U, 0x101U);
    const auto start = static_cast<std::uint32_t>(bytes.size()); U32(bytes, 20U, start);
    for (std::size_t i = 0; i < strings.size(); ++i) {
        assert(strings[i].size() < 128U);
        U32(bytes, 28U + 4U * i, static_cast<std::uint32_t>(bytes.size()) - start);
        bytes.push_back(static_cast<std::uint8_t>(strings[i].size()));
        bytes.push_back(static_cast<std::uint8_t>(strings[i].size()));
        bytes.insert(bytes.end(), strings[i].begin(), strings[i].end()); bytes.push_back(0U);
    }
    while (bytes.size() % 4U) bytes.push_back(0U);
    U32(bytes, 4U, static_cast<std::uint32_t>(bytes.size()));
    return bytes;
}
birch::guard::ZipArchive Fixture(bool overlay = false) {
    const auto global = Pool({"title", "res/drawable/icon.png", "res/drawable/panel.9.png", "res/raw/sound.bin"});
    const auto types = Pool({"drawable", "raw", "string"});
    const auto keys = Pool({"title", "icon", "panel", "sound"});
    Bytes package(284U);
    U16(package, 0U, 0x200U); U16(package, 2U, 284U); U32(package, 8U, 0x7fU);
    U32(package, 268U, 284U);
    U32(package, 276U, 284U + static_cast<std::uint32_t>(types.size()));
    package.insert(package.end(), types.begin(), types.end());
    package.insert(package.end(), keys.begin(), keys.end());
    if (overlay) {
        const auto at = package.size(); package.resize(at + 8U);
        U16(package, at, 0x204U); U16(package, at + 2U, 8U); U32(package, at + 4U, 8U);
    }
    U32(package, 4U, static_cast<std::uint32_t>(package.size()));
    Bytes table(12U); U16(table, 0U, 2U); U16(table, 2U, 12U); U32(table, 8U, 1U);
    table.insert(table.end(), global.begin(), global.end()); table.insert(table.end(), package.begin(), package.end());
    U32(table, 4U, static_cast<std::uint32_t>(table.size()));
    birch::guard::ZipArchive archive;
    archive.Add({"resources.arsc", table});
    for (const auto path : {"res/drawable/icon.png", "res/drawable/panel.9.png", "res/raw/sound.bin"})
        archive.Add({path, {1U, 2U, 3U}});
    return archive;
}
void AddDynamicApi(birch::guard::ZipArchive& archive, const char* name) {
    birch::dex::ClassSpec klass; klass.descriptor = "Lresource/Fixture;";
    birch::dex::MethodSpec method; method.name = "run"; method.return_type = "V";
    method.access_flags = 9U; method.body.code_units = {0x0071U, 0U, 0U, 0x000eU};
    method.body.references.push_back({birch::dex::MethodReference{
        "Landroid/content/res/Resources;", name, "V", {}}, 1U, false});
    klass.direct_methods.push_back(std::move(method));
    birch::dex::DexBuilder builder; builder.AddClass(std::move(klass));
    archive.Add({"classes.dex", builder.Build()});
}
}
int main() {
    using namespace birch::guard;
    using detail::ResourceObfuscator;
    for (unsigned mode = 1U; mode <= 3U; ++mode) {
        auto archive = Fixture(); auto config = GuardConfig::Defaults();
        config.resources.rename_names = (mode & 1U) != 0U;
        config.resources.rename_files = (mode & 2U) != 0U;
        const auto plan = ResourceObfuscator::Plan(archive, config);
        assert(plan.names().size() == (config.resources.rename_names ? 4U : 0U));
        assert(plan.paths().size() == (config.resources.rename_files ? 3U : 0U));
        plan.Apply(archive);
        const auto table = ArscTable::Parse(archive.Find("resources.arsc")->data);
        const auto strings = table.strings();
        assert(std::find(strings.begin(), strings.end(), "title") != strings.end()); // user value untouched
        if (config.resources.rename_names) assert((table.resource_names() == std::vector<std::string>{"BirchGuard"}));
        for (const auto& [old_path, new_path] : plan.paths()) {
            assert(archive.Find(old_path) == nullptr && archive.Find(new_path) != nullptr);
            assert(std::any_of(new_path.begin(), new_path.end(), [](unsigned char c) { return c >= 128U; }));
            if (old_path.ends_with(".9.png")) assert(new_path.ends_with(".9.png"));
            assert(std::find(strings.begin(), strings.end(), new_path) != strings.end());
        }
        const auto roundtrip = ZipArchive::Read(archive.Write());
        for (const auto& [old_path, new_path] : plan.paths()) {
            (void)old_path; assert(roundtrip.Find(new_path) != nullptr);
            assert((roundtrip.Find(new_path)->flags & 0x800U) != 0U);
        }
    }
    auto config = GuardConfig::Defaults(); config.resources.rename_names = true; config.resources.rename_files = true;
    for (const auto name : {"getIdentifier", "getResourceEntryName", "getDeclaredField"}) {
        auto archive = Fixture(); AddDynamicApi(archive, name);
        assert(ResourceObfuscator::Plan(archive, config).names().empty());
    }
    auto paths = Fixture(); AddDynamicApi(paths, "openNonAsset");
    assert(ResourceObfuscator::Plan(paths, config).paths().empty());
    auto native = Fixture(); native.Add({"lib/arm64-v8a/libfixture.so", {0U}});
    const auto native_plan = ResourceObfuscator::Plan(native, config);
    assert(native_plan.names().empty()); assert(!native_plan.paths().contains("res/raw/sound.bin"));
    assert(ResourceObfuscator::Plan(Fixture(true), config).names().empty());
    auto assets = Fixture(); assets.Add({"assets/config", {'t','i','t','l','e'}});
    assert(!ResourceObfuscator::Plan(assets, config).names().contains("title"));
    std::cout << "Resource plans: independent modes, values, Unicode ZIP, ninepatch and compatibility locks passed\n";
}
