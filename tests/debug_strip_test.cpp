#include "birch/dex/builder.h"
#include "birch/dex/code.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/verifier.h"
#include "birch/guard/zip.h"
#include "birch/guard/pipeline.h"
#include "birch/io/file.h"
#include "support/synthetic_apk.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <string_view>

namespace {

constexpr std::uint16_t kDebugInfoItem = 0x2003U;

bool HasDebugMap(const birch::dex::DexFile& dex) {
    return std::any_of(dex.map().begin(), dex.map().end(),
                       [](const auto& item) {
                           return item.type == kDebugInfoItem;
                       });
}

void AssertNoDebugMetadata(const birch::dex::DexFile& dex) {
    assert(!HasDebugMap(dex));
    for (std::size_t class_index = 0U;
         class_index < dex.classes().size(); ++class_index) {
        assert(dex.classes()[class_index].source_file_idx == 0xffffffffU);
        const auto& data = dex.class_data(class_index);
        for (const auto* methods : {&data.direct_methods,
                                    &data.virtual_methods}) {
            for (const auto& method : *methods) {
                if (method.code_off == 0U) continue;
                assert(birch::dex::DecodeCodeItem(dex, method.code_off)
                           .debug_info_off == 0U);
            }
        }
    }
}

} // namespace

int main() {
    using namespace birch::dex;

    DexBuilder builder(38U);
    ClassSpec klass;
    klass.descriptor = "Ldebug/Secret;";
    klass.source_file = "SensitiveSource.kt";
    MethodSpec method;
    method.name = "run";
    method.parameter_types = {"I"};
    method.body.registers_size = 1U;
    method.body.ins_size = 1U;
    method.body.code_units = {0x000eU};
    DebugInfoSpec debug;
    debug.line_start = 7331U;
    debug.parameter_names = {std::string("sensitiveParameterName")};
    DebugEventSpec local;
    local.kind = DebugEventKind::StartLocal;
    local.register_index = 0U;
    local.name = "sensitiveLocalName";
    local.type = "I";
    debug.events.push_back(std::move(local));
    method.body.debug_info = std::move(debug);
    klass.direct_methods.push_back(std::move(method));
    builder.AddClass(std::move(klass));

    const auto source = DexFile::Parse(builder.Build());
    assert(HasDebugMap(source));
    const auto debug_item = std::find_if(
        source.map().begin(), source.map().end(),
        [](const auto& item) { return item.type == kDebugInfoItem; });
    assert(debug_item != source.map().end());
    auto debug_end = source.bytes().size();
    for (const auto& item : source.map()) {
        if (item.offset > debug_item->offset) {
            debug_end = std::min(debug_end,
                                 static_cast<std::size_t>(item.offset));
        }
    }
    const auto stripped_bytes = source.StripDebugInfo();
    assert(std::all_of(stripped_bytes.begin() + debug_item->offset,
                       stripped_bytes.begin() +
                           static_cast<std::ptrdiff_t>(debug_end),
                       [](std::uint8_t value) { return value == 0U; }));
    const auto stripped = DexFile::Parse(stripped_bytes);
    assert(VerifyDex(stripped, VerificationLevel::Full).ok);
    AssertNoDebugMetadata(stripped);

    auto config = birch::guard::GuardConfig::Defaults();
    for (auto& [id, pass] : config.passes) pass.enabled = false;
    config.passes.at("anti_analysis.debug_info_removal").enabled = true;
    config.output.write_mapping = true;
    config.output.mapping_file = "debug-strip-test-mapping.txt";
    const auto pipeline = birch::guard::GuardPipeline::FromConfig(std::move(config));
    const std::filesystem::path input = "debug-strip-source.apk";
    birch::io::WriteBinaryFile(input, birch::test::ApkWithDex(source.bytes()).Write());
    const std::filesystem::path output = "debug-strip-test.apk";
    pipeline.TransformApk(input, output);
    assert(std::filesystem::exists(output));
    assert(std::filesystem::exists("debug-strip-test-mapping.txt"));

    const auto archive = birch::guard::ZipArchive::Read(output);
    std::size_t dex_count = 0U;
    for (const auto& entry : archive.entries()) {
        if (entry.name != "classes.dex" &&
            !(entry.name.starts_with("classes") &&
              entry.name.ends_with(".dex"))) {
            assert(entry.name != "birch-mapping.txt");
            assert(entry.name != "debug-strip-test-mapping.txt");
            continue;
        }
        const auto dex = DexFile::Parse(entry.data);
        assert(VerifyDex(dex, VerificationLevel::Full).ok);
        AssertNoDebugMetadata(dex);
        ++dex_count;
    }
    assert(dex_count != 0U);
    std::filesystem::remove(input);
    std::filesystem::remove(output);
    std::filesystem::remove(output.string() + ".techniques.txt");
    std::filesystem::remove("debug-strip-test-mapping.txt");
    return 0;
}
