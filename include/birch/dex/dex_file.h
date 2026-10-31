#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <map>

namespace birch::dex {

enum class DexErrorCode {
    InvalidMagic,
    UnsupportedVersion,
    Truncated,
    InvalidHeader,
    InvalidEndian,
    IntegerOverflow,
    OutOfBounds,
    InvalidIndex,
    InvalidString,
    InvalidMap,
    InvalidClassData,
};

class DexParseError final : public std::runtime_error {
public:
    DexParseError(DexErrorCode code, std::size_t offset, std::string message);

    [[nodiscard]] DexErrorCode code() const noexcept { return code_; }
    [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

private:
    DexErrorCode code_;
    std::size_t offset_;
};

struct DexHeader {
    std::uint32_t checksum{};
    std::vector<std::uint8_t> signature;
    std::uint32_t file_size{};
    std::uint32_t header_size{};
    std::uint32_t endian_tag{};
    std::uint32_t link_size{};
    std::uint32_t link_off{};
    std::uint32_t map_off{};
    std::uint32_t string_ids_size{};
    std::uint32_t string_ids_off{};
    std::uint32_t type_ids_size{};
    std::uint32_t type_ids_off{};
    std::uint32_t proto_ids_size{};
    std::uint32_t proto_ids_off{};
    std::uint32_t field_ids_size{};
    std::uint32_t field_ids_off{};
    std::uint32_t method_ids_size{};
    std::uint32_t method_ids_off{};
    std::uint32_t class_defs_size{};
    std::uint32_t class_defs_off{};
    std::uint32_t data_size{};
    std::uint32_t data_off{};
    std::uint32_t container_size{};
    std::uint32_t header_offset{};
};

struct DexString {
    std::uint32_t utf16_length{};
    std::string mutf8;
    std::uint32_t data_offset{};
    std::uint32_t encoded_size{};
};

struct DexTypeId { std::uint32_t descriptor_idx{}; };
struct DexProtoId {
    std::uint32_t shorty_idx{};
    std::uint32_t return_type_idx{};
    std::uint32_t parameters_off{};
};
struct DexFieldId {
    std::uint16_t class_idx{};
    std::uint16_t type_idx{};
    std::uint32_t name_idx{};
};
struct DexMethodId {
    std::uint16_t class_idx{};
    std::uint16_t proto_idx{};
    std::uint32_t name_idx{};
};
struct DexCallSiteId {
    std::uint32_t encoded_array_off{};
    std::uint32_t item_offset{};
};
struct DexMethodHandle {
    std::uint16_t handle_type{};
    std::uint16_t member_idx{};
    std::uint32_t item_offset{};
};
struct DexClassDef {
    std::uint32_t class_idx{};
    std::uint32_t access_flags{};
    std::uint32_t superclass_idx{};
    std::uint32_t interfaces_off{};
    std::uint32_t source_file_idx{};
    std::uint32_t annotations_off{};
    std::uint32_t class_data_off{};
    std::uint32_t static_values_off{};
};

struct DexMapItem {
    std::uint16_t type{};
    std::uint32_t size{};
    std::uint32_t offset{};
};

struct DexEncodedField {
    std::uint32_t field_idx{};
    std::uint32_t access_flags{};
};
struct DexEncodedMethod {
    std::uint32_t method_idx{};
    std::uint32_t access_flags{};
    std::uint32_t code_off{};
};
struct DexClassData {
    std::vector<DexEncodedField> static_fields;
    std::vector<DexEncodedField> instance_fields;
    std::vector<DexEncodedMethod> direct_methods;
    std::vector<DexEncodedMethod> virtual_methods;
};

class DexFile final {
public:
    static DexFile Parse(std::span<const std::uint8_t> bytes);
    static DexFile Parse(const std::vector<std::uint8_t>& bytes) {
        return Parse(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    }

    [[nodiscard]] const DexHeader& header() const noexcept { return header_; }
    [[nodiscard]] std::uint8_t version() const noexcept { return version_; }
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept { return bytes_; }
    [[nodiscard]] const std::vector<DexString>& strings() const noexcept { return strings_; }
    [[nodiscard]] const std::vector<DexTypeId>& types() const noexcept { return types_; }
    [[nodiscard]] const std::vector<DexProtoId>& protos() const noexcept { return protos_; }
    [[nodiscard]] const std::vector<DexFieldId>& fields() const noexcept { return fields_; }
    [[nodiscard]] const std::vector<DexMethodId>& methods() const noexcept { return methods_; }
    [[nodiscard]] const std::vector<DexCallSiteId>& call_sites() const noexcept { return call_sites_; }
    [[nodiscard]] const std::vector<DexMethodHandle>& method_handles() const noexcept { return method_handles_; }
    [[nodiscard]] const std::vector<DexClassDef>& classes() const noexcept { return classes_; }
    [[nodiscard]] const std::vector<DexMapItem>& map() const noexcept { return map_; }
    [[nodiscard]] const DexClassData& class_data(std::size_t index) const;

    [[nodiscard]] std::string descriptor(std::uint32_t type_idx) const;
    [[nodiscard]] std::string string(std::uint32_t string_idx) const;
    [[nodiscard]] std::vector<std::uint16_t> type_list(std::uint32_t offset) const;
    [[nodiscard]] std::string proto_key(std::uint32_t proto_idx) const;
    [[nodiscard]] std::string field_key(std::uint32_t field_idx) const;
    [[nodiscard]] std::string method_key(std::uint32_t method_idx) const;

    // Replaces an existing string_data_item in place. Its encoded byte size must
    // be identical because string_data_items are a packed variable-size section.
    [[nodiscard]] std::vector<std::uint8_t> ReplaceStringInPlace(
        std::uint32_t string_idx, std::string_view mutf8, std::uint32_t utf16_length) const;
    [[nodiscard]] std::vector<std::uint8_t> ReplaceStringsInPlace(
        const std::map<std::uint32_t, std::pair<std::string, std::uint32_t>>& replacements) const;
    [[nodiscard]] std::vector<std::uint8_t> ReplaceStrings(
        const std::map<std::uint32_t, std::pair<std::string, std::uint32_t>>& replacements) const;
    [[nodiscard]] std::vector<std::uint8_t> StripDebugInfo() const;
    [[nodiscard]] std::vector<std::uint8_t> RewriteBogusBranches(
        double intensity, std::uint64_t seed, std::size_t& changed) const;
    [[nodiscard]] std::vector<std::uint8_t> RewriteClassDataIndices(
        const std::vector<std::uint32_t>& field_remap,
        const std::vector<std::uint32_t>& method_remap) const;
    [[nodiscard]] std::vector<std::uint8_t> RewriteMemberIndicesRelocated(
        const std::vector<std::uint32_t>& field_remap,
        const std::vector<std::uint32_t>& method_remap) const;

    // The original bytes are retained so no-op round trips are byte-for-byte stable.
    [[nodiscard]] std::vector<std::uint8_t> Write() const { return bytes_; }
    [[nodiscard]] bool VerifyChecksums() const;
    [[nodiscard]] bool VerifyCanonicalOrder(std::string* issue = nullptr) const;

private:
    friend class DexContainer;
    DexFile() = default;
    static DexFile ParseContainerEntry(std::span<const std::uint8_t> bytes,
                                       std::uint32_t header_offset);
    void ParseImpl(std::span<const std::uint8_t> bytes, std::uint32_t header_offset);
    void ParseHeader(std::span<const std::uint8_t> bytes);
    void ParseIds(std::span<const std::uint8_t> bytes);
    void ParseMap(std::span<const std::uint8_t> bytes);
    void ParseClassData(std::span<const std::uint8_t> bytes);
    void CheckRange(std::uint64_t offset, std::uint64_t size, DexErrorCode code,
                    std::string_view what) const;
    void CheckIndex(std::uint32_t index, std::uint32_t size, std::size_t offset,
                    std::string_view what) const;
    void EnsureStandaloneWritable() const;

    std::vector<std::uint8_t> bytes_;
    DexHeader header_;
    std::uint8_t version_{};
    std::vector<DexString> strings_;
    std::vector<DexTypeId> types_;
    std::vector<DexProtoId> protos_;
    std::vector<DexFieldId> fields_;
    std::vector<DexMethodId> methods_;
    std::vector<DexCallSiteId> call_sites_;
    std::vector<DexMethodHandle> method_handles_;
    std::vector<DexClassDef> classes_;
    std::vector<DexMapItem> map_;
    std::vector<DexClassData> class_data_;
};

class DexContainer final {
public:
    static DexContainer Parse(std::span<const std::uint8_t> bytes);
    static DexContainer Parse(const std::vector<std::uint8_t>& bytes) {
        return Parse(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    }

    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept { return bytes_; }
    [[nodiscard]] const std::vector<DexFile>& dex_files() const noexcept { return dex_files_; }
    [[nodiscard]] std::size_t size() const noexcept { return dex_files_.size(); }
    [[nodiscard]] const DexFile& dex(std::size_t index) const { return dex_files_.at(index); }

private:
    std::vector<std::uint8_t> bytes_;
    std::vector<DexFile> dex_files_;
};

} // namespace birch::dex
