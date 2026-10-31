#include "birch/dex/builder.h"
#include "birch/dex/cfg.h"
#include "birch/dex/checksum.h"
#include "birch/dex/cloner.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/program.h"
#include "birch/dex/verifier.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <fstream>

namespace {

void PatchU32(std::vector<std::uint8_t>& bytes, std::size_t offset,
              std::uint32_t value) {
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

void UpdateAt(std::vector<std::uint8_t>& bytes, std::size_t base,
              std::size_t file_size) {
    const auto signature = birch::dex::Sha1(std::span<const std::uint8_t>(
        bytes.data() + base + 0x20U, file_size - 0x20U));
    std::copy(signature.begin(), signature.end(), bytes.begin() + base + 0x0cU);
    const auto checksum = birch::dex::Adler32(std::span<const std::uint8_t>(
        bytes.data() + base + 0x0cU, file_size - 0x0cU));
    PatchU32(bytes, base + 0x08U, checksum);
}

} // namespace

int main() {
    birch::dex::DexBuilder builder;
    builder.AddString(std::string("embedded\0nul", 12U));
    builder.AddString(std::string("\xed\xa0\x80", 3U)); // unpaired UTF-16 surrogate in MUTF-8
    birch::dex::ClassSpec klass;
    klass.descriptor = "Lbirch/fake/Business;";
    klass.direct_methods.push_back({"run", "V", {}, 0x0009U, {1U, 0U, 0U, {0x000eU}}});
    builder.AddClass(std::move(klass));
    const auto bytes = builder.Build();
    const auto dex = birch::dex::DexFile::Parse(bytes);
    assert(dex.classes().size() == 1U);
    assert(dex.methods().size() == 1U);
    assert(dex.fields().empty());
    assert(dex.header().field_ids_off == 0U);
    assert(std::any_of(dex.strings().begin(), dex.strings().end(),
                       [](const auto& value) {
                           return value.mutf8 ==
                               std::string("embedded\xc0\x80nul", 13U);
                       }));
    assert(std::any_of(dex.strings().begin(), dex.strings().end(),
                       [](const auto& value) {
                           return value.mutf8 == std::string("\xed\xa0\x80", 3U);
                       }));
    const auto& data = dex.class_data(0U);
    assert(data.direct_methods.size() == 1U);
    assert(data.direct_methods.front().code_off != 0U);
    const auto code = birch::dex::DecodeCodeItem(dex, data.direct_methods.front().code_off);
    const auto ir = birch::dex::BuildMethodIr(code);
    const birch::dex::ControlFlowGraph cfg(ir);
    assert(cfg.Verify());
    assert(dex.VerifyChecksums());
    const auto expanded = dex.ReplaceStrings({{0U, {"this_is_a_longer_string", 23U}}});
    const auto expanded_dex = birch::dex::DexFile::Parse(expanded);
    assert(expanded_dex.VerifyChecksums());

    birch::dex::DexBuilder symbolic_builder(38U);
    birch::dex::ClassSpec symbolic_class;
    symbolic_class.descriptor = "Lbirch/builder/Symbolic;";
    symbolic_class.source_file = "Symbolic.kt";
    birch::dex::MethodSpec symbolic_method;
    symbolic_method.name = "exercise";
    symbolic_method.body.registers_size = 2U;
    symbolic_method.body.outs_size = 1U;
    symbolic_method.body.code_units = {
        0x001aU, 0U,              // const-string v0, string@BBBB
        0x001cU, 0U,              // const-class v0, type@BBBB
        0x0060U, 0U,              // sget v0, field@BBBB
        0x0071U, 0U, 0x0000U,     // invoke-static {}, method@BBBB
        0x00ffU, 0U,              // const-method-type v0, proto@BBBB
        0x000eU,                  // return-void
        0x010dU,                  // move-exception v1
        0x000eU,                  // return-void
    };
    using Body = birch::dex::MethodBodySpec;
    symbolic_method.body.references = {
        {std::string("symbolic-value"), 1U, false},
        {Body::TypeReference{"Ljava/lang/String;"}, 3U, false},
        {Body::FieldReference{"Ljava/lang/System;", "out",
                              "Ljava/io/PrintStream;"}, 5U, false},
        {Body::MethodReference{"Ljava/lang/System;", "gc", "V", {}},
         7U, false},
        {Body::ProtoReference{"Ljava/lang/String;", {"I"}}, 10U, false},
    };
    symbolic_method.body.try_regions = {
        {2U, 2U, {{std::string("Ljava/lang/Exception;"), 12U},
                  {std::nullopt, 12U}}},
    };
    symbolic_class.direct_methods.push_back(std::move(symbolic_method));
    symbolic_builder.AddClass(std::move(symbolic_class));
    const auto symbolic_bytes = symbolic_builder.Build();
    const auto symbolic_dex = birch::dex::DexFile::Parse(symbolic_bytes);
    assert(birch::dex::VerifyDex(symbolic_dex,
                                 birch::dex::VerificationLevel::Full).ok);
    assert(symbolic_dex.string(symbolic_dex.classes().front().source_file_idx) ==
           "Symbolic.kt");
    const auto symbolic_code = birch::dex::DecodeCodeItem(
        symbolic_dex,
        symbolic_dex.class_data(0U).direct_methods.front().code_off);
    assert(symbolic_code.instructions.at(0U).opcode == 0x1aU);
    assert(symbolic_dex.string(symbolic_code.instructions.at(0U).code_units.at(1U)) ==
           "symbolic-value");
    assert(symbolic_dex.descriptor(
               symbolic_code.instructions.at(1U).code_units.at(1U)) ==
           "Ljava/lang/String;");
    assert(symbolic_dex.field_key(
               symbolic_code.instructions.at(2U).code_units.at(1U)) ==
           "Ljava/lang/System;->out:Ljava/io/PrintStream;");
    assert(symbolic_dex.method_key(
               symbolic_code.instructions.at(3U).code_units.at(1U)) ==
           "Ljava/lang/System;->gc()V");
    assert(symbolic_dex.proto_key(
               symbolic_code.instructions.at(4U).code_units.at(1U)) ==
           "(I)Ljava/lang/String;");
    assert(symbolic_code.tries.size() == 1U);
    assert(symbolic_code.tries.front().handlers.size() == 2U);
    assert(symbolic_dex.descriptor(
               *symbolic_code.tries.front().handlers.front().type_idx) ==
           "Ljava/lang/Exception;");
    assert(!symbolic_code.tries.front().handlers.back().type_idx.has_value());

    birch::dex::DexBuilder jumbo_builder(38U);
    for (std::uint32_t i = 0U; i < 65536U; ++i) {
        auto value = std::string("jumbo-string-");
        value.append(5U - std::min<std::size_t>(5U, std::to_string(i).size()),
                     '0');
        value.append(std::to_string(i));
        jumbo_builder.AddString(std::move(value));
    }
    constexpr std::string_view jumbo_value = "zzzz-jumbo-target";
    birch::dex::ClassSpec jumbo_class;
    jumbo_class.descriptor = "Lbirch/builder/Jumbo;";
    birch::dex::MethodSpec jumbo_method;
    jumbo_method.name = "load";
    jumbo_method.body.registers_size = 2U;
    jumbo_method.body.code_units = {
        0x0328U,             // goto target
        0x001aU, 0U,        // const-string v0, string@BBBB
        0x000eU,             // target: return-void
        0x010dU,             // handler: move-exception v1
        0x000eU,             // return-void
    };
    jumbo_method.body.string_references.push_back(
        {std::string(jumbo_value), 2U});
    jumbo_method.body.try_regions.push_back(
        {1U, 2U, {{std::nullopt, 4U}}});
    birch::dex::DebugInfoSpec jumbo_debug;
    jumbo_debug.line_start = 1U;
    birch::dex::DebugEventSpec jumbo_advance;
    jumbo_advance.kind = birch::dex::DebugEventKind::AdvancePc;
    jumbo_advance.address_difference = 3U;
    jumbo_debug.events.push_back(jumbo_advance);
    jumbo_method.body.debug_info = std::move(jumbo_debug);
    jumbo_class.direct_methods.push_back(std::move(jumbo_method));
    jumbo_builder.AddClass(std::move(jumbo_class));
    const auto jumbo_bytes = jumbo_builder.Build();
    const auto jumbo_dex = birch::dex::DexFile::Parse(jumbo_bytes);
    assert(birch::dex::VerifyDex(jumbo_dex,
                                 birch::dex::VerificationLevel::Full).ok);
    const auto jumbo_class_index = std::distance(
        jumbo_dex.classes().begin(),
        std::find_if(jumbo_dex.classes().begin(), jumbo_dex.classes().end(),
                     [&](const auto& definition) {
                         return jumbo_dex.descriptor(definition.class_idx) ==
                                "Lbirch/builder/Jumbo;";
                     }));
    assert(jumbo_class_index <
           static_cast<std::ptrdiff_t>(jumbo_dex.classes().size()));
    const auto jumbo_code = birch::dex::DecodeCodeItem(
        jumbo_dex,
        jumbo_dex.class_data(static_cast<std::size_t>(jumbo_class_index))
            .direct_methods.front().code_off);
    assert(jumbo_code.instructions.at(0U).opcode == 0x28U);
    assert(jumbo_code.instructions.at(0U).targets.front() == 4U);
    assert(jumbo_code.instructions.at(1U).opcode == 0x1bU);
    const auto jumbo_string_index =
        static_cast<std::uint32_t>(
            jumbo_code.instructions.at(1U).code_units.at(1U)) |
        static_cast<std::uint32_t>(
            jumbo_code.instructions.at(1U).code_units.at(2U)) << 16U;
    assert(jumbo_string_index > 0xffffU);
    assert(jumbo_dex.string(jumbo_string_index) == jumbo_value);
    assert(jumbo_code.tries.size() == 1U);
    assert(jumbo_code.tries.front().start_address == 1U);
    assert(jumbo_code.tries.front().instruction_count == 3U);
    assert(jumbo_code.tries.front().handlers.front().address == 5U);
    birch::dex::DexClassCloner jumbo_cloner(jumbo_dex);
    const auto cloned_jumbo = jumbo_cloner.Clone(
        static_cast<std::size_t>(jumbo_class_index));
    assert(cloned_jumbo.direct_methods.front().body.debug_info.has_value());
    assert(cloned_jumbo.direct_methods.front().body.debug_info->events.front()
               .address_difference == 4U);

    birch::dex::DexBuilder v41_builder(41U);
    birch::dex::ClassSpec v41_class;
    v41_class.descriptor = "Lbirch/v41/Business;";
    v41_class.direct_methods.push_back({"run", "V", {}, 0x0009U,
                                        {1U, 0U, 0U, {0x000eU}}});
    v41_builder.AddClass(std::move(v41_class));
    auto container_bytes = v41_builder.Build();
    const auto standalone_v41 = birch::dex::DexFile::Parse(container_bytes);
    assert(standalone_v41.header().header_size == 0x78U);
    assert(standalone_v41.header().container_size == container_bytes.size());
    assert(standalone_v41.header().header_offset == 0U);
    assert(birch::dex::VerifyDex(standalone_v41,
                                 birch::dex::VerificationLevel::Full).ok);
    assert(birch::dex::DexContainer::Parse(container_bytes).size() == 1U);
    if (const auto* output = std::getenv("BIRCH_V41_OUTPUT")) {
        std::ofstream stream(output, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(container_bytes.data()),
                     static_cast<std::streamsize>(container_bytes.size()));
    }
    const auto first_size = container_bytes.size();
    const auto second_offset = container_bytes.size();
    const auto second_file_size = 0x78U + 4U + 2U * 12U;
    container_bytes.resize(second_offset + second_file_size, 0U);
    std::copy_n("dex\n041\0", 8U, container_bytes.begin() + second_offset);
    PatchU32(container_bytes, second_offset + 0x20U,
             static_cast<std::uint32_t>(second_file_size));
    PatchU32(container_bytes, second_offset + 0x24U, 0x78U);
    PatchU32(container_bytes, second_offset + 0x28U, 0x12345678U);
    const auto second_map = static_cast<std::uint32_t>(second_offset + 0x78U);
    PatchU32(container_bytes, second_offset + 0x34U, second_map);
    PatchU32(container_bytes, second_offset + 0x68U, 28U);
    PatchU32(container_bytes, second_offset + 0x6cU, second_map);
    PatchU32(container_bytes, second_offset + 0x70U,
             static_cast<std::uint32_t>(container_bytes.size()));
    PatchU32(container_bytes, second_offset + 0x74U,
             static_cast<std::uint32_t>(second_offset));
    std::vector<std::uint8_t> map;
    AppendU32(map, 2U);
    AppendU16(map, 0x0000U); AppendU16(map, 0U); AppendU32(map, 1U);
    AppendU32(map, static_cast<std::uint32_t>(second_offset));
    AppendU16(map, 0x1000U); AppendU16(map, 0U); AppendU32(map, 1U);
    AppendU32(map, second_map);
    std::copy(map.begin(), map.end(), container_bytes.begin() + second_map);
    PatchU32(container_bytes, 0x70U, static_cast<std::uint32_t>(container_bytes.size()));
    UpdateAt(container_bytes, 0U, first_size);
    UpdateAt(container_bytes, second_offset, second_file_size);
    const auto container = birch::dex::DexContainer::Parse(container_bytes);
    assert(container.size() == 2U);
    assert(container.dex(0U).version() == 41U);
    assert(container.dex(1U).header().header_offset == second_offset);
    assert(container.dex(0U).VerifyChecksums());
    assert(container.dex(1U).VerifyChecksums());
    const auto program = birch::dex::DexProgram::Parse(
        {{"container.dex", container_bytes}});
    assert(program.dex_count() == 2U);
    assert(program.dex_name(0U) == "container.dex@0x0");
    return 0;
}
