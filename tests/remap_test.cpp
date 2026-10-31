#include "birch/dex/builder.h"
#include "birch/dex/checksum.h"
#include "birch/dex/code.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/remap.h"
#include "birch/dex/verifier.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <tuple>
#include <vector>

namespace {

std::uint32_t ReadU32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(bytes.at(offset)) |
           static_cast<std::uint32_t>(bytes.at(offset + 1U)) << 8U |
           static_cast<std::uint32_t>(bytes.at(offset + 2U)) << 16U |
           static_cast<std::uint32_t>(bytes.at(offset + 3U)) << 24U;
}

void PatchU16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::uint8_t>(value);
    bytes.at(offset + 1U) = static_cast<std::uint8_t>(value >> 8U);
}

void PatchU32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned shift = 0U; shift < 32U; shift += 8U) {
        bytes.at(offset + shift / 8U) = static_cast<std::uint8_t>(value >> shift);
    }
}

void AppendU16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void AppendU32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    for (unsigned shift = 0U; shift < 32U; shift += 8U) {
        bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void Align4(std::vector<std::uint8_t>& bytes) {
    while ((bytes.size() & 3U) != 0U) bytes.push_back(0U);
}

struct ExtendedDex {
    std::vector<std::uint8_t> bytes;
    std::uint32_t method_handle_off{};
    std::uint32_t call_site_array_off{};
    std::uint32_t first_method_annotation_idx_off{};
    std::uint32_t first_parameter_annotation_idx_off{};
    std::uint32_t second_method_annotation_idx_off{};
};

ExtendedDex AddDex038Sections(std::vector<std::uint8_t> bytes) {
    const auto source = birch::dex::DexFile::Parse(bytes);
    assert(source.version() >= 38U);
    assert(source.methods().size() == 2U);
    assert(source.classes().size() == 2U);
    assert(source.strings().size() < 256U);
    assert(source.protos().size() < 256U);

    Align4(bytes);
    const auto call_site_off = static_cast<std::uint32_t>(bytes.size());
    AppendU32(bytes, 0U);

    const auto method_handle_off = static_cast<std::uint32_t>(bytes.size());
    AppendU16(bytes, 4U); // METHOD_HANDLE_TYPE_INVOKE_STATIC
    AppendU16(bytes, 0U);
    AppendU16(bytes, 0U); // old method index
    AppendU16(bytes, 0U);

    const auto call_site_array_off = static_cast<std::uint32_t>(bytes.size());
    bytes.push_back(4U);
    bytes.push_back(0x16U); bytes.push_back(0U); // method_handle@0
    bytes.push_back(0x17U); bytes.push_back(static_cast<std::uint8_t>(source.methods()[0].name_idx));
    bytes.push_back(0x15U); bytes.push_back(static_cast<std::uint8_t>(source.methods()[0].proto_idx));
    bytes.push_back(0x1aU); bytes.push_back(0U); // bootstrap argument method@0
    PatchU32(bytes, call_site_off, call_site_array_off);

    Align4(bytes);
    const auto annotation_set_off = static_cast<std::uint32_t>(bytes.size());
    AppendU32(bytes, 0U);
    const auto annotation_set_ref_off = static_cast<std::uint32_t>(bytes.size());
    AppendU32(bytes, 0U);

    const auto first_directory_off = static_cast<std::uint32_t>(bytes.size());
    AppendU32(bytes, 0U); AppendU32(bytes, 0U); AppendU32(bytes, 1U); AppendU32(bytes, 1U);
    const auto first_method_idx_off = static_cast<std::uint32_t>(bytes.size());
    AppendU32(bytes, 0U); AppendU32(bytes, annotation_set_off);
    const auto first_parameter_idx_off = static_cast<std::uint32_t>(bytes.size());
    AppendU32(bytes, 0U); AppendU32(bytes, annotation_set_ref_off);

    const auto second_directory_off = static_cast<std::uint32_t>(bytes.size());
    AppendU32(bytes, 0U); AppendU32(bytes, 0U); AppendU32(bytes, 1U); AppendU32(bytes, 0U);
    const auto second_method_idx_off = static_cast<std::uint32_t>(bytes.size());
    AppendU32(bytes, 1U); AppendU32(bytes, annotation_set_off);

    const auto class_defs_off = ReadU32(bytes, 0x64U);
    PatchU32(bytes, class_defs_off + 20U, first_directory_off);
    PatchU32(bytes, class_defs_off + 32U + 20U, second_directory_off);

    Align4(bytes);
    const auto new_map_off = static_cast<std::uint32_t>(bytes.size());
    auto map = source.map();
    for (auto& item : map) {
        if (item.type == 0x1000U) item.offset = new_map_off;
    }
    map.push_back({0x0007U, 1U, call_site_off});
    map.push_back({0x0008U, 1U, method_handle_off});
    map.push_back({0x1002U, 1U, annotation_set_ref_off});
    map.push_back({0x1003U, 1U, annotation_set_off});
    map.push_back({0x2005U, 1U, call_site_array_off});
    map.push_back({0x2006U, 2U, first_directory_off});
    std::sort(map.begin(), map.end(), [](const auto& left, const auto& right) {
        return std::tie(left.offset, left.type) < std::tie(right.offset, right.type);
    });
    AppendU32(bytes, static_cast<std::uint32_t>(map.size()));
    for (const auto& item : map) {
        AppendU16(bytes, item.type); AppendU16(bytes, 0U);
        AppendU32(bytes, item.size); AppendU32(bytes, item.offset);
    }
    PatchU32(bytes, 0x34U, new_map_off);
    PatchU32(bytes, 0x20U, static_cast<std::uint32_t>(bytes.size()));
    PatchU32(bytes, 0x68U, static_cast<std::uint32_t>(bytes.size()) - ReadU32(bytes, 0x6cU));
    birch::dex::UpdateDexChecksums(bytes);
    return {std::move(bytes), method_handle_off, call_site_array_off,
            first_method_idx_off, first_parameter_idx_off, second_method_idx_off};
}

} // namespace

int main() {
    birch::dex::DexBuilder builder;
    birch::dex::ClassSpec klass;
    klass.descriptor = "Lremap/Test;";
    klass.direct_methods.push_back({"run", "V", {}, 0x0009U, {1U, 0U, 0U, {0x000eU}}});
    builder.AddClass(std::move(klass));
    const auto dex = birch::dex::DexFile::Parse(builder.Build());
    const auto remap = birch::dex::BuildCanonicalRemap(dex, {false, false, false, false, false});
    const auto bytes = birch::dex::ApplyIdRemap(dex, remap);
    assert(birch::dex::DexFile::Parse(bytes).VerifyChecksums());
    const auto descriptor_string_idx = dex.types()[dex.classes()[0].class_idx].descriptor_idx;
    const auto shortened_bytes = dex.ReplaceStrings({{descriptor_string_idx, {"La;", 3U}}});
    const auto shortened = birch::dex::DexFile::Parse(shortened_bytes);
    assert(shortened.descriptor(shortened.classes()[0].class_idx) == "La;");
    assert(shortened.VerifyChecksums());
    const auto canonicalized = birch::dex::DexFile::Parse(
        birch::dex::ApplyIdRemap(shortened, birch::dex::BuildCanonicalRemap(shortened)));
    assert(canonicalized.VerifyCanonicalOrder());
    assert(canonicalized.descriptor(canonicalized.classes()[0].class_idx) == "La;");
    bool rejected_short_in_place = false;
    try {
        (void)dex.ReplaceStringsInPlace({{descriptor_string_idx, {"La;", 3U}}});
    } catch (const std::length_error&) {
        rejected_short_in_place = true;
    }
    assert(rejected_short_in_place);

    birch::dex::DexBuilder existing_alias_builder(38U);
    existing_alias_builder.AddString("target");
    birch::dex::ClassSpec existing_alias_class;
    existing_alias_class.descriptor = "Lremap/ExistingAlias;";
    existing_alias_class.direct_methods.push_back(
        {"source", "V", {}, 0x0009U, {1U, 0U, 0U, {0x000eU}}});
    existing_alias_builder.AddClass(std::move(existing_alias_class));
    const auto existing_alias_source = birch::dex::DexFile::Parse(
        existing_alias_builder.Build());
    const auto source_string = std::find_if(
        existing_alias_source.strings().begin(),
        existing_alias_source.strings().end(),
        [](const auto& value) { return value.mutf8 == "source"; });
    const auto target_string = std::find_if(
        existing_alias_source.strings().begin(),
        existing_alias_source.strings().end(),
        [](const auto& value) { return value.mutf8 == "target"; });
    assert(source_string != existing_alias_source.strings().end());
    assert(target_string != existing_alias_source.strings().end());
    std::vector<std::uint32_t> existing_aliases(
        existing_alias_source.strings().size());
    for (std::size_t i = 0U; i < existing_aliases.size(); ++i) {
        existing_aliases[i] = static_cast<std::uint32_t>(i);
    }
    const auto source_string_idx = static_cast<std::uint32_t>(
        source_string - existing_alias_source.strings().begin());
    const auto target_string_idx = static_cast<std::uint32_t>(
        target_string - existing_alias_source.strings().begin());
    existing_aliases[source_string_idx] = target_string_idx;
    const auto existing_alias_output = birch::dex::DexFile::Parse(
        birch::dex::ApplyIdRemap(
            existing_alias_source,
            birch::dex::BuildCanonicalRemap(
                existing_alias_source, {}, existing_aliases)));
    assert(existing_alias_output.VerifyCanonicalOrder());
    const auto& existing_alias_method = existing_alias_output.methods().at(
        existing_alias_output.class_data(0U).direct_methods.front().method_idx);
    assert(existing_alias_output.string(existing_alias_method.name_idx) ==
           "target");

    birch::dex::DexBuilder member_builder(38U);
    birch::dex::ClassSpec first_class;
    first_class.descriptor = "Lremap/A;";
    first_class.direct_methods.push_back({"aa", "V", {}, 0x0009U, {1U, 0U, 0U, {0x000eU}}});
    member_builder.AddClass(std::move(first_class));
    birch::dex::ClassSpec second_class;
    second_class.descriptor = "Lremap/B;";
    second_class.direct_methods.push_back({"bb", "V", {}, 0x0009U, {1U, 0U, 0U, {0x000eU}}});
    member_builder.AddClass(std::move(second_class));

    const auto extended = AddDex038Sections(member_builder.Build());
    const auto member_dex = birch::dex::DexFile::Parse(extended.bytes);
    assert(member_dex.call_sites().size() == 1U);
    assert(member_dex.method_handles().size() == 1U);
    assert(member_dex.method_handles()[0].member_idx == 0U);

    std::vector<std::uint32_t> field_identity(member_dex.fields().size());
    std::vector<std::uint32_t> method_swap{1U, 0U};
    const auto relocated = member_dex.RewriteMemberIndicesRelocated(field_identity, method_swap);
    const auto relocated_dex = birch::dex::DexFile::Parse(relocated);
    assert(birch::dex::VerifyDex(relocated_dex, birch::dex::VerificationLevel::Code).ok);
    assert(relocated_dex.method_handles()[0].member_idx == 1U);
    assert(relocated.at(extended.call_site_array_off + 8U) == 1U);
    assert(ReadU32(relocated, extended.first_method_annotation_idx_off) == 1U);
    assert(ReadU32(relocated, extended.first_parameter_annotation_idx_off) == 1U);
    assert(ReadU32(relocated, extended.second_method_annotation_idx_off) == 0U);
    for (std::size_t i = 1; i < relocated_dex.map().size(); ++i) {
        assert(relocated_dex.map()[i - 1U].offset <= relocated_dex.map()[i].offset);
    }

    auto invalid_handle = extended.bytes;
    PatchU16(invalid_handle, extended.method_handle_off + 2U, 1U);
    birch::dex::UpdateDexChecksums(invalid_handle);
    bool rejected = false;
    try {
        (void)birch::dex::DexFile::Parse(invalid_handle);
    } catch (const birch::dex::DexParseError&) {
        rejected = true;
    }
    assert(rejected);

    birch::dex::DexBuilder jumbo_builder(38U);
    constexpr std::string_view old_jumbo_value = "!jumbo-target";
    constexpr std::string_view new_jumbo_value = "zzzzzz-jumbo-target";
    jumbo_builder.AddString(std::string(old_jumbo_value));
    for (std::uint32_t i = 0U; i < 65536U; ++i) {
        std::ostringstream name;
        name << 'a' << std::setw(5) << std::setfill('0') << i;
        jumbo_builder.AddString(name.str());
    }
    birch::dex::ClassSpec jumbo_class;
    jumbo_class.descriptor = "Lremap/Jumbo;";
    birch::dex::MethodSpec jumbo_method;
    jumbo_method.name = "load";
    jumbo_method.body = {1U, 0U, 0U, {0x001aU, 0U, 0x000eU}};
    jumbo_method.body.string_references.push_back({std::string(old_jumbo_value), 1U});
    jumbo_class.direct_methods.push_back(std::move(jumbo_method));
    jumbo_builder.AddClass(std::move(jumbo_class));
    auto jumbo_source_bytes = jumbo_builder.Build();
    auto jumbo_source = birch::dex::DexFile::Parse(jumbo_source_bytes);
    const auto target = std::find_if(jumbo_source.strings().begin(), jumbo_source.strings().end(),
                                     [](const auto& value) {
        return value.mutf8 == old_jumbo_value;
    });
    assert(target != jumbo_source.strings().end());
    const auto old_target_index = static_cast<std::uint32_t>(
        std::distance(jumbo_source.strings().begin(), target));
    assert(old_target_index <= 0xffffU);
    jumbo_source_bytes = jumbo_source.ReplaceStrings({
        {old_target_index,
         {std::string(new_jumbo_value), static_cast<std::uint32_t>(new_jumbo_value.size())}}
    });
    jumbo_source = birch::dex::DexFile::Parse(jumbo_source_bytes);
    const auto jumbo_remap = birch::dex::BuildCanonicalRemap(jumbo_source);
    assert(jumbo_remap.strings.at(old_target_index) > 0xffffU);
    const auto jumbo_output = birch::dex::DexFile::Parse(
        birch::dex::ApplyIdRemap(jumbo_source, jumbo_remap));
    assert(birch::dex::VerifyDex(jumbo_output,
                                 birch::dex::VerificationLevel::Full).ok);
    const auto& jumbo_data = jumbo_output.class_data(0U);
    const auto jumbo_code = birch::dex::DecodeCodeItem(
        jumbo_output, jumbo_data.direct_methods.front().code_off);
    assert(jumbo_code.instructions.front().opcode == 0x1bU);
    const auto jumbo_index =
        static_cast<std::uint32_t>(jumbo_code.instructions.front().code_units.at(1U)) |
        static_cast<std::uint32_t>(jumbo_code.instructions.front().code_units.at(2U)) << 16U;
    assert(jumbo_output.string(jumbo_index) == new_jumbo_value);

    birch::dex::DexBuilder prefix_builder(38U);
    birch::dex::ClassSpec prefix_class;
    prefix_class.descriptor = "Lremap/Prefix;";
    prefix_class.virtual_methods.push_back(
        {"work", "V", {}, 0x0001U, {1U, 1U, 0U, {0x000eU}}});
    prefix_builder.AddClass(std::move(prefix_class));
    const auto prefix_source = birch::dex::DexFile::Parse(prefix_builder.Build());
    const auto prefix_code_off =
        prefix_source.class_data(0U).virtual_methods.front().code_off;
    const auto prefix_output = birch::dex::DexFile::Parse(
        birch::dex::RewriteCodePrefixes(prefix_source, {{
            prefix_code_off,
            {0x0038U, 0x0004U, 0x0228U, 0x0000U}, // if-eqz v0, original; goto original
            {}
        }}));
    assert(birch::dex::VerifyDex(prefix_output,
                                 birch::dex::VerificationLevel::Full).ok);
    const auto relocated_prefix_code = birch::dex::DecodeCodeItem(
        prefix_output, prefix_output.class_data(0U).virtual_methods.front().code_off);
    assert(relocated_prefix_code.insns.size() == 5U);
    assert(relocated_prefix_code.instructions.at(0U).opcode == 0x38U);
    assert(relocated_prefix_code.instructions.at(0U).targets.at(0U) == 4U);
    assert(relocated_prefix_code.instructions.at(1U).opcode == 0x28U);
    assert(relocated_prefix_code.instructions.at(1U).targets.at(0U) == 4U);

    birch::dex::DexBuilder exception_builder(38U);
    birch::dex::ClassSpec exception_class;
    exception_class.descriptor = "Lremap/ExceptionPrefix;";
    exception_class.virtual_methods.push_back(
        {"work", "V", {}, 0x0001U, {2U, 1U, 0U, {0x000eU}}});
    exception_builder.AddClass(std::move(exception_class));
    const auto exception_source = birch::dex::DexFile::Parse(exception_builder.Build());
    const auto exception_code_off =
        exception_source.class_data(0U).virtual_methods.front().code_off;
    birch::dex::CodePrefix exception_prefix;
    exception_prefix.code_off = exception_code_off;
    exception_prefix.code_units = {
        0x0012U, // const/4 v0, #0
        0x0027U, // throw v0 -> deterministic NullPointerException
        0x000dU, // move-exception v0
        0x0128U, // goto original entry
    };
    exception_prefix.try_regions.push_back({1U, 1U, {{std::nullopt, 2U}}});
    const auto exception_output = birch::dex::DexFile::Parse(
        birch::dex::RewriteCodePrefixes(exception_source, {exception_prefix}));
    assert(birch::dex::VerifyDex(exception_output,
                                 birch::dex::VerificationLevel::Full).ok);
    const auto exception_code = birch::dex::DecodeCodeItem(
        exception_output,
        exception_output.class_data(0U).virtual_methods.front().code_off);
    assert(exception_code.tries.size() == 1U);
    assert(exception_code.tries.front().start_address == 1U);
    assert(exception_code.tries.front().handlers.front().address == 2U);

    birch::dex::DexBuilder replacement_builder(38U);
    birch::dex::ClassSpec replacement_class;
    replacement_class.descriptor = "Lremap/Replacement;";
    birch::dex::MethodSpec replacement_method;
    replacement_method.name = "work";
    replacement_method.body.registers_size = 1U;
    replacement_method.body.code_units = {
        0x1012U,             // const/4 v0, #1
        0x0038U, 5U,         // if-eqz v0, handler
        0x001cU, 0U,         // const-class v0, type@BBBB
        0x000eU,             // return-void
        0x000dU,             // move-exception v0
        0x000eU,             // return-void
    };
    replacement_method.body.references.push_back({
        birch::dex::TypeReference{"Ljava/lang/String;"}, 4U, false});
    replacement_method.body.try_regions.push_back(
        {3U, 2U, {{std::nullopt, 6U}}});
    birch::dex::DebugInfoSpec replacement_debug;
    replacement_debug.line_start = 7U;
    birch::dex::DebugEventSpec debug_advance;
    debug_advance.kind = birch::dex::DebugEventKind::AdvancePc;
    debug_advance.address_difference = 3U;
    replacement_debug.events.push_back(debug_advance);
    replacement_method.body.debug_info = std::move(replacement_debug);
    replacement_class.direct_methods.push_back(std::move(replacement_method));
    replacement_builder.AddClass(std::move(replacement_class));
    const auto replacement_source = birch::dex::DexFile::Parse(
        replacement_builder.Build());
    const auto replacement_code_off =
        replacement_source.class_data(0U).direct_methods.front().code_off;
    birch::dex::CodePrefix replacement_spec;
    replacement_spec.code_off = replacement_code_off;
    replacement_spec.linear_replacements.emplace(0U,
        std::vector<std::uint16_t>{
            0x0014U, 0x5a5aU, 0U, // const v0, #0x5a5a
            0x00d7U, 0x5a5bU,     // xor-int/lit16 v0, v0, #0x5a5b -> 1
        });
    const auto replacement_output = birch::dex::DexFile::Parse(
        birch::dex::RewriteCodePrefixes(replacement_source,
                                        {replacement_spec}));
    assert(birch::dex::VerifyDex(replacement_output,
                                 birch::dex::VerificationLevel::Full).ok);
    const auto replaced_code = birch::dex::DecodeCodeItem(
        replacement_output,
        replacement_output.class_data(0U).direct_methods.front().code_off);
    assert(replaced_code.insns.size() == 12U);
    assert(replaced_code.instructions.front().opcode == 0x14U);
    assert(replaced_code.instructions.at(1U).opcode == 0xd7U);
    const auto branch = std::find_if(
        replaced_code.instructions.begin(), replaced_code.instructions.end(),
        [](const auto& instruction) { return instruction.opcode == 0x38U; });
    assert(branch != replaced_code.instructions.end());
    assert(branch->targets.front() == 10U);
    assert(replaced_code.tries.size() == 1U);
    assert(replaced_code.tries.front().start_address == 7U);
    assert(replaced_code.tries.front().instruction_count == 2U);
    assert(replaced_code.tries.front().handlers.front().address == 10U);
    assert(replaced_code.debug_info_off != 0U);

    // Reordering must not create a physical fallthrough from an unreachable
    // executable alignment island into a live return block. String helpers
    // use this shape for payload alignment, and ART verifies the invented edge
    // with otherwise undefined live registers.
    birch::dex::DexBuilder island_builder(38U);
    birch::dex::ClassSpec island_class;
    island_class.descriptor = "Lremap/UnreachableIsland;";
    birch::dex::MethodSpec island_method;
    island_method.name = "value";
    island_method.return_type = "I";
    island_method.access_flags = 0x0009U;
    island_method.body.registers_size = 2U;
    island_method.body.code_units = {
        0x0013U, 0x0001U,       // 0000: const/16 v0, #1
        0x0038U, 0x0004U,       // 0002: if-eqz v0, 0006
        0x0029U, 0xfffcU,       // 0004: goto/16 0000
        0x000fU,                // 0006: return v0
        0x0114U, 0U, 0U,       // 0007: unreachable const v1, #0
        0x0300U, 0x0001U,       // 000a: array-data, width=1
        0x0001U, 0U, 0x0041U,  //       size=1, data='A'
    };
    island_class.direct_methods.push_back(std::move(island_method));
    island_builder.AddClass(std::move(island_class));
    const auto island_source = birch::dex::DexFile::Parse(
        island_builder.Build());
    assert(birch::dex::VerifyDex(island_source,
                                 birch::dex::VerificationLevel::Full).ok);
    birch::dex::CodePrefix island_reorder;
    island_reorder.code_off =
        island_source.class_data(0U).direct_methods.front().code_off;
    island_reorder.reorder_blocks = true;
    island_reorder.reorder_seed = 0x123456789abcdef0ULL;
    const auto island_output = birch::dex::DexFile::Parse(
        birch::dex::RewriteCodePrefixes(island_source, {island_reorder}));
    assert(birch::dex::VerifyDex(island_output,
                                 birch::dex::VerificationLevel::Full).ok);
    const auto island_code = birch::dex::DecodeCodeItem(
        island_output,
        island_output.class_data(0U).direct_methods.front().code_off);
    assert(std::any_of(
        island_code.instructions.begin(), island_code.instructions.end(),
        [](const auto &instruction) {
          return instruction.opcode == 0x2aU &&
                 !instruction.targets.empty() &&
                 instruction.targets.front() == instruction.offset;
        }));
    return 0;
}
