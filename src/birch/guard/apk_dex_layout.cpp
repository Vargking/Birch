#include "apk_dex_layout.h"

#include "birch/dex/cloner.h"
#include "birch/guard/axml.h"
#include "birch/io/apk_entries.h"

#include <algorithm>
#include <charconv>
#include <optional>
#include <stdexcept>

namespace birch::guard::detail {
namespace {

std::uint32_t Read(std::span<const std::uint8_t> data, std::size_t at,
                   std::size_t width) {
    if (at > data.size() || width > data.size() - at) {
        throw std::runtime_error("truncated manifest SDK attribute");
    }
    std::uint32_t value = 0U;
    for (std::size_t i = 0U; i < width; ++i) {
        value |= static_cast<std::uint32_t>(data[at + i]) << (8U * i);
    }
    return value;
}

unsigned MinSdk(const ZipArchive& archive) {
    const auto* manifest = archive.Find("AndroidManifest.xml");
    if (manifest == nullptr) throw std::runtime_error("APK has no manifest");
    const auto document = AxmlDocument::Parse(manifest->data);
    const auto& strings = document.strings();
    std::optional<unsigned> result;
    for (const auto& chunk : document.chunks()) {
        if (chunk.type != 0x0102U) continue;
        const auto node = document.bytes().subspan(chunk.offset, chunk.size);
        if (chunk.header_size < 16U || chunk.size - chunk.header_size < 20U) {
            throw std::runtime_error("truncated manifest start element");
        }
        const auto ext = static_cast<std::size_t>(chunk.header_size);
        const auto element = Read(node, ext + 4U, 4U);
        if (element >= strings.size()) throw std::runtime_error("invalid manifest element name");
        if (strings[element] != "uses-sdk") continue;
        const auto start = Read(node, ext + 8U, 2U);
        const auto stride = Read(node, ext + 10U, 2U);
        const auto count = Read(node, ext + 12U, 2U);
        if (start < 20U || stride < 20U || ext + start > node.size() ||
            count > (node.size() - ext - start) / stride) {
            throw std::runtime_error("invalid manifest SDK attribute layout");
        }
        for (std::size_t i = 0U; i < count; ++i) {
            const auto at = ext + start + i * stride;
            const auto ns = Read(node, at, 4U);
            const auto name = Read(node, at + 4U, 4U);
            if (ns >= strings.size() || name >= strings.size()) {
                throw std::runtime_error("invalid manifest SDK attribute name");
            }
            if (strings[ns] != "http://schemas.android.com/apk/res/android" ||
                strings[name] != "minSdkVersion") continue;
            if (result.has_value()) throw std::runtime_error("duplicate minSdkVersion");
            if (Read(node, at + 12U, 2U) != 8U) {
                throw std::runtime_error("invalid manifest SDK typed value");
            }
            const auto type = Read(node, at + 15U, 1U);
            const auto value = Read(node, at + 16U, 4U);
            unsigned sdk = 1U;
            if (type == 0x10U || type == 0x11U) {
                if (value == 0U || value > 0x7fffffffU) {
                    throw std::runtime_error("invalid numeric minSdkVersion");
                }
                sdk = value;
            } else if (type == 0x03U) {
                if (value >= strings.size()) throw std::runtime_error("invalid SDK string index");
                const auto& text = strings[value];
                unsigned parsed = 0U;
                const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), parsed);
                if (error == std::errc{} && end == text.data() + text.size() && parsed != 0U) sdk = parsed;
                // Preview codenames/resources are not proof of native multidex.
            }
            result = sdk;
        }
    }
    return result.value_or(1U);
}

std::string NormalizeType(std::string value,
    const std::map<std::string, std::string, std::less<>>& classes) {
    const auto first = value.find_first_not_of('[');
    if (first == std::string::npos) return value;
    const auto found = classes.find(value.substr(first));
    if (found != classes.end()) value.replace(first, std::string::npos, found->second);
    return value;
}

bool Fits(const dex::DexFile& file, const dex::IdLimits& limits) {
    return file.strings().size() <= limits.strings && file.types().size() <= limits.types &&
        file.protos().size() <= limits.protos && file.fields().size() <= limits.fields &&
        file.methods().size() <= limits.methods && file.call_sites().size() <= limits.call_sites &&
        file.method_handles().size() <= limits.method_handles;
}

} // namespace

ApkDexLayout::ApkDexLayout(const ZipArchive& source) : min_sdk_(MinSdk(source)) {
    const auto names = io::DexEntryNames(source);
    if (names.empty() || names.front() != "classes.dex") {
        throw std::runtime_error("APK has no primary classes.dex");
    }
    single_input_ = names.size() == 1U;
    const auto primary = dex::DexFile::Parse(source.Find("classes.dex")->data);
    for (const auto& type : primary.classes()) primary_classes_.insert(primary.descriptor(type.class_idx));
    for (std::size_t i = 0U; i < primary.types().size(); ++i) {
        primary_types_.insert(primary.descriptor(static_cast<std::uint32_t>(i)));
    }
}

bool ApkDexLayout::MergeGeneratedDex(ZipArchive& archive, std::string_view generated,
                                    const dex::IdLimits& limits) const {
    if (!single_input_ && min_sdk_ >= 21U) return false;
    if (generated == "classes.dex") throw std::invalid_argument("generated DEX aliases primary");
    const auto* primary = archive.Find("classes.dex");
    const auto* extra = archive.Find(generated);
    if (primary == nullptr || extra == nullptr) throw std::runtime_error("missing DEX during safe merge");
    limits.Validate();
    const auto program = dex::DexProgram::Parse({{"classes.dex", primary->data},
                                                {std::string(generated), extra->data}});
    const auto handles = program.classes();
    const auto merged = dex::BuildDexPartition(program, handles);
    if (!Fits(dex::DexFile::Parse(merged.bytes), limits)) {
        throw std::runtime_error("generated classes exceed primary DEX ID limits; refusing an unbootstrapped secondary DEX");
    }
    // Do not mutate the archive until cloning, verification and budgets pass.
    archive.FindMutable("classes.dex")->data = merged.bytes;
    if (!archive.RemoveEntry(generated)) throw std::logic_error("generated DEX disappeared during merge");
    return true;
}

void ApkDexLayout::Verify(const ZipArchive& output,
    const std::map<std::string, std::string, std::less<>>& classes) const {
    if (MinSdk(output) != min_sdk_) throw std::runtime_error("transformation changed minSdkVersion");
    const auto names = io::DexEntryNames(output);
    if (names.empty() || names.front() != "classes.dex") throw std::runtime_error("output has no primary DEX");
    if (min_sdk_ >= 21U) return;
    if (single_input_ && names.size() != 1U) {
        throw std::runtime_error("legacy single-DEX input requires a single-DEX output; no multidex bootstrap was installed");
    }
    std::set<std::string, std::less<>> primary;
    std::set<std::string, std::less<>> secondary;
    for (const auto& name : names) {
        const auto file = dex::DexFile::Parse(output.Find(name)->data);
        auto& descriptors = name == "classes.dex" ? primary : secondary;
        for (const auto& type : file.classes()) descriptors.insert(file.descriptor(type.class_idx));
    }
    for (const auto& original : primary_classes_) {
        const auto current = NormalizeType(original, classes);
        if (secondary.contains(current) && !primary.contains(current)) {
            throw std::runtime_error("legacy startup class moved out of primary DEX: " + current);
        }
    }
    std::set<std::string, std::less<>> allowed;
    for (const auto& type : primary_types_) allowed.insert(NormalizeType(type, classes));
    const auto main = dex::DexFile::Parse(output.Find("classes.dex")->data);
    for (std::size_t i = 0U; i < main.types().size(); ++i) {
        const auto type = main.descriptor(static_cast<std::uint32_t>(i));
        const auto element = type.substr(type.find_first_not_of('['));
        if (secondary.contains(element) && !allowed.contains(type) && !allowed.contains(element)) {
            throw std::runtime_error("new primary-to-secondary dependency before legacy bootstrap: " + type);
        }
    }
}

} // namespace birch::guard::detail
