#pragma once

#include "birch/dex/dex_file.h"
#include "birch/dex/code_layout.h"

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace birch::dex {

struct IdRemap {
    std::vector<std::uint32_t> strings;
    std::vector<std::uint32_t> types;
    std::vector<std::uint32_t> protos;
    std::vector<std::uint32_t> fields;
    std::vector<std::uint32_t> methods;
    // Optional old-string -> representative-old-string aliases. String IDs are
    // still kept unique; member/reflection references may share a representative.
    std::vector<std::uint32_t> string_aliases;
};

struct RemapOptions {
    bool sort_strings{true};
    bool sort_types{true};
    bool sort_protos{true};
    bool sort_fields{true};
    bool sort_methods{true};
};

struct CodePrefix {
    struct CatchHandler {
        std::optional<std::uint32_t> type_idx;
        std::uint32_t address{};
    };
    struct TryRegion {
        std::uint32_t start_address{};
        std::uint32_t instruction_count{};
        std::vector<CatchHandler> handlers;
    };
    std::uint32_t code_off{};
    std::vector<std::uint16_t> code_units;
    std::vector<TryRegion> try_regions;
    bool reorder_blocks{};
    std::uint64_t reorder_seed{};
    // Optional complete code_item body replacement. The replacement already
    // contains final branch/payload displacements; the DEX data writer still
    // relocates the surrounding code_item and class_data offsets. This is used
    // by transforms such as basic-block control-flow flattening that cannot be
    // represented as an entry prefix or a linear instruction substitution.
    std::optional<std::vector<std::uint16_t>> replacement_code_units;
    std::optional<std::uint16_t> replacement_registers_size;
    std::optional<std::uint16_t> replacement_outs_size;
    std::vector<TryRegion> replacement_try_regions;
    // Replaces one decoded instruction with a non-empty, linear fallthrough
    // sequence. Keys are original code-unit offsets. A payload may only be
    // replaced by an equal-width sequence of canonical nops, which is useful
    // after lowering fill-array-data into generated code.
    std::map<std::uint32_t, std::vector<std::uint16_t>> linear_replacements;
    // Optional exclusive ends for const/32 + same-register xor/add-int/lit16
    // spans. Only the first instruction is replaced; interior arithmetic is
    // removed. No branch, handler, or try boundary may enter the interior.
    std::map<std::uint32_t, std::uint32_t> arithmetic_span_ends;
    // Single-entry, single-continuation executable regions replaced by a
    // linear callsite. Internal branches may be removed; external interior
    // entries, payloads, monitors and exception-context boundaries are forbidden.
    // A region wholly inside one unchanged try context is allowed; the call
    // remains covered by the original handlers and the caller retains its locks.
    // The caller is responsible for proving the new call boundary's types
    // and live values. The writer independently rechecks structural safety.
    std::map<std::uint32_t, std::uint32_t> outline_span_ends;
};

IdRemap BuildCanonicalRemap(
    const DexFile& dex, const RemapOptions& options = {},
    const std::vector<std::uint32_t>& string_aliases = {});
std::vector<std::uint32_t> ConstrainRemapToEncodedWidth(
    const std::vector<std::uint32_t>& desired_remap);
std::vector<std::uint8_t> ApplyIdRemap(const DexFile& dex, const IdRemap& remap);
std::vector<std::uint8_t> RewriteCodePrefixes(const DexFile& dex,
                                              const std::vector<CodePrefix>& prefixes,
                                              CodeAddressMaps* addresses = nullptr);

} // namespace birch::dex
