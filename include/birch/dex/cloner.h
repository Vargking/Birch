#pragma once

#include "birch/dex/builder.h"
#include "birch/dex/partition.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace birch::dex {

struct CloneOptions {
    bool preserve_debug_info{true};
};

class DexClassCloner final {
public:
    explicit DexClassCloner(const DexFile& source, CloneOptions options = {});
    ~DexClassCloner();

    DexClassCloner(const DexClassCloner&) = delete;
    DexClassCloner& operator=(const DexClassCloner&) = delete;
    DexClassCloner(DexClassCloner&&) noexcept;
    DexClassCloner& operator=(DexClassCloner&&) noexcept;

    [[nodiscard]] ClassSpec Clone(std::size_t class_index);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

struct RepartitionOptions {
    PartitionOptions partition;
    CloneOptions clone;
    std::optional<std::uint32_t> output_version;
    std::function<void(std::size_t current, std::size_t total,
                       std::string_view phase)> progress;
};

struct RepartitionedDex {
    std::vector<std::uint8_t> bytes;
    std::vector<ClassHandle> classes;
    std::uint32_t version{};
};

[[nodiscard]] RepartitionedDex BuildDexPartition(
    const DexProgram& program, std::span<const ClassHandle> classes,
    const CloneOptions& options = {},
    std::optional<std::uint32_t> output_version = std::nullopt);

[[nodiscard]] std::vector<RepartitionedDex> RepartitionProgram(
    const DexProgram& program, const RepartitionOptions& options = {});

} // namespace birch::dex
