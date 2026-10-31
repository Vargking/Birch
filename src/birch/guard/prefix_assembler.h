#pragma once

#include "birch/dex/remap.h"

#include <cstdint>
#include <initializer_list>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace birch::guard::detail {

class PrefixAssembler final {
public:
    PrefixAssembler(std::size_t limit, std::size_t try_limit,
                    std::size_t block_limit);
    [[nodiscard]] bool AppendOpaqueBranch(std::uint16_t reg, bool invert);
    [[nodiscard]] bool AppendCompactOpaqueSplit(std::uint16_t scratch,
                                                std::uint64_t state);
    [[nodiscard]] bool AppendPatternRandomization(std::uint16_t scratch,
                                                  std::size_t rounds,
                                                  std::uint64_t state);
    [[nodiscard]] bool AppendInstructionPattern(std::uint16_t scratch,
                                                std::uint16_t second,
                                                std::uint64_t state);
    [[nodiscard]] bool AppendRuntimeOpaque(std::uint16_t scratch,
                                           std::uint16_t method_index,
                                           std::uint64_t state);
    [[nodiscard]] bool AppendDataBarrier(std::uint16_t scratch,
                                         std::uint64_t state);
    [[nodiscard]] bool AppendMixedDispatch(std::uint16_t predicate,
                                           std::uint16_t scratch);
    [[nodiscard]] bool AppendSsaPollution(std::uint16_t predicate,
                                          std::uint16_t first,
                                          std::uint16_t second,
                                          std::uint64_t state);
    [[nodiscard]] bool AppendDataflowPollution(std::uint16_t first,
                                               std::uint16_t second,
                                               std::uint64_t state);
    [[nodiscard]] bool AppendRegisterShape(std::uint16_t first,
                                           std::uint16_t second,
                                           std::uint64_t state);
    [[nodiscard]] bool AppendMultiState(std::uint16_t first, std::uint16_t second);
    [[nodiscard]] bool AppendExceptionDispatch(std::uint16_t scratch,
                                               std::uint16_t helper_method,
                                               std::uint64_t state);
    [[nodiscard]] bool AppendExceptionMaze(std::uint16_t scratch,
                                           std::uint16_t helper_method,
                                           std::uint64_t state);
    [[nodiscard]] bool AppendSequentialExceptionMaze(
        std::uint16_t scratch, std::uint16_t helper_method,
        std::uint64_t state);
    [[nodiscard]] bool AppendSharedHandlerFanIn(std::uint16_t predicate,
                                                 std::uint16_t scratch,
                                                 std::uint16_t helper_method,
                                                 std::uint64_t state);
    [[nodiscard]] bool AppendDecompilerMaze(std::uint16_t predicate,
                                             std::uint16_t scratch,
                                             std::uint16_t helper_method,
                                             std::uint64_t state);
    void EnableBlockReordering(std::uint64_t seed) noexcept;
    [[nodiscard]] bool ReplaceInstruction(
        std::uint32_t offset, std::uint32_t original_width,
        std::vector<std::uint16_t> replacement);
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] std::size_t added_blocks() const noexcept;
    [[nodiscard]] std::size_t remaining_blocks() const noexcept;
    [[nodiscard]] dex::CodePrefix Finish(std::uint32_t code_off) &&;
private:
    [[nodiscard]] bool Reserve(std::size_t width,
                               std::size_t blocks = 0U) const noexcept;
    [[nodiscard]] bool AppendSwitch(std::uint16_t scratch, bool sparse);
    std::size_t limit_{};
    std::size_t try_limit_{};
    std::size_t block_limit_{};
    std::size_t added_blocks_{};
    std::vector<std::uint16_t> code_;
    std::vector<dex::CodePrefix::TryRegion> tries_;
    bool reorder_blocks_{};
    std::uint64_t reorder_seed_{};
    std::size_t replacement_growth_{};
    std::map<std::uint32_t, std::vector<std::uint16_t>> replacements_;
};

} // namespace birch::guard::detail
