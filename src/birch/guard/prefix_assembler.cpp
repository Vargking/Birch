#include "birch/guard/dex_lowering.h"
#include "strength_policy.h"

#include "birch/dex/code.h"
#include "birch/dex/ir.h"
#include "birch/dex/remap.h"
#include "birch/dex/type_analysis.h"
#include "birch/dex/verifier.h"
#include "birch/guard/scope.h"
#include "birch/guard/constant_runtime.h"
#include "birch/guard/opaque_runtime.h"
#include "birch/utils/hash.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <iterator>
#include <initializer_list>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>

#include "prefix_assembler.h"

namespace birch::guard::detail {

PrefixAssembler::PrefixAssembler(std::size_t limit, std::size_t try_limit,
                    std::size_t block_limit)
        : limit_(limit), try_limit_(try_limit), block_limit_(block_limit) {}

bool PrefixAssembler::AppendOpaqueBranch(std::uint16_t reg, bool invert) {
        if (reg > 0xffU || !Reserve(4U, 2U)) return false;
        code_.push_back(static_cast<std::uint16_t>(
            (invert ? 0x39U : 0x38U) | (reg << 8U)));
        code_.push_back(4U);
        // Skip the local goto and continue at the next prefix/original body.
        code_.push_back(0x0029U);
        code_.push_back(0x0002U);
        added_blocks_ += 2U;
        return true;
    }

bool PrefixAssembler::AppendCompactOpaqueSplit(std::uint16_t scratch,
                                                std::uint64_t state) {
        if (scratch > 0x0fU || !Reserve(8U, 2U)) return false;
        auto xor_key = static_cast<std::uint8_t>((state >> 17U) | 1U);
        auto add_key = static_cast<std::uint8_t>((state >> 41U) | 1U);
        code_.insert(code_.end(), {
            static_cast<std::uint16_t>(0x1012U | (scratch << 8U)),
            static_cast<std::uint16_t>(0x38U | (scratch << 8U)), 5U,
            static_cast<std::uint16_t>(0xdfU | (scratch << 8U)),
            static_cast<std::uint16_t>(scratch | (xor_key << 8U)),
            0x0328U,
            static_cast<std::uint16_t>(0xd8U | (scratch << 8U)),
            static_cast<std::uint16_t>(scratch | (add_key << 8U)),
        });
        added_blocks_ += 2U;
        return true;
    }

bool PrefixAssembler::AppendPatternRandomization(std::uint16_t scratch,
                                                  std::size_t rounds,
                                                  std::uint64_t state) {
        if (scratch > 0x0fU || rounds == 0U ||
            rounds > std::numeric_limits<std::size_t>::max() / 6U ||
            !Reserve(rounds * 6U, 1U)) {
            return false;
        }
        for (std::size_t round = 0U; round < rounds; ++round) {
            state ^= state << 13U;
            state ^= state >> 7U;
            state ^= state << 17U;
            const auto literal = static_cast<std::uint16_t>(state | 1U);
            const auto first = static_cast<std::uint8_t>((state >> 19U) | 1U);
            const auto second = static_cast<std::uint8_t>((state >> 43U) | 1U);
            code_.insert(code_.end(), {
                static_cast<std::uint16_t>(0x13U | (scratch << 8U)), literal,
                static_cast<std::uint16_t>(0xdfU | (scratch << 8U)),
                static_cast<std::uint16_t>(scratch | (first << 8U)),
                static_cast<std::uint16_t>(0xd8U | (scratch << 8U)),
                static_cast<std::uint16_t>(scratch | (second << 8U)),
            });
        }
        ++added_blocks_;
        return true;
    }

bool PrefixAssembler::AppendInstructionPattern(std::uint16_t scratch,
                                                std::uint16_t second,
                                                std::uint64_t state) {
        if (scratch > 0x0fU || second > 0x0fU || scratch == second ||
            !Reserve(24U, 2U)) {
            return false;
        }
        const auto first = static_cast<std::uint16_t>(state | 1U);
        const auto other = static_cast<std::uint16_t>((state >> 19U) | 1U);
        const auto selector = static_cast<std::uint8_t>((state >> 47U) % 3U);
        code_.insert(code_.end(), {
            static_cast<std::uint16_t>(0x13U | (scratch << 8U)), first,
            static_cast<std::uint16_t>(0x13U | (second << 8U)), other,
        });
        for (std::size_t round = 0U; round < 8U; ++round) {
            const auto variant = static_cast<std::uint8_t>(
                (selector + round) % 3U);
            if (variant == 0U) {
                code_.push_back(static_cast<std::uint16_t>(
                    0xb7U | (scratch << 8U) | (second << 12U)));
                code_.push_back(static_cast<std::uint16_t>(
                    0xb0U | (second << 8U) | (scratch << 12U)));
            } else if (variant == 1U) {
                code_.push_back(static_cast<std::uint16_t>(
                    0xb2U | (second << 8U) | (scratch << 12U)));
                code_.push_back(static_cast<std::uint16_t>(
                    0xb7U | (scratch << 8U) | (second << 12U)));
            } else {
                code_.push_back(static_cast<std::uint16_t>(
                    0xb1U | (scratch << 8U) | (second << 12U)));
                code_.push_back(static_cast<std::uint16_t>(
                    0xb7U | (second << 8U) | (scratch << 12U)));
            }
        }
        code_.insert(code_.end(), {
            static_cast<std::uint16_t>(0x32U | (scratch << 8U) |
                                       (second << 12U)),
            2U,
            static_cast<std::uint16_t>(0xdfU | (scratch << 8U)),
            static_cast<std::uint16_t>(scratch | 0x5d00U),
        });
        added_blocks_ += 2U;
        return true;
    }

bool PrefixAssembler::AppendRuntimeOpaque(std::uint16_t scratch,
                                           std::uint16_t method_index,
                                           std::uint64_t state) {
        if (scratch > 0xffU || !Reserve(21U, 4U)) return false;
        code_.push_back(0x0071U); // invoke-static {}, method@BBBB
        code_.push_back(method_index);
        code_.push_back(0U);
        code_.push_back(static_cast<std::uint16_t>(
            0x0aU | (scratch << 8U))); // move-result
        code_.push_back(static_cast<std::uint16_t>(
            0x39U | (scratch << 8U))); // if-nez -> original entry
        code_.push_back(17U);

        // The false arm is verifier-live but unreachable because every helper
        // validates its synchronized volatile state invariant before returning.
        const auto first = static_cast<std::uint32_t>(state);
        code_.push_back(static_cast<std::uint16_t>(
            0x14U | (scratch << 8U))); // const vA, #BBBBBBBB
        code_.push_back(static_cast<std::uint16_t>(first));
        code_.push_back(static_cast<std::uint16_t>(first >> 16U));
        code_.push_back(static_cast<std::uint16_t>(0xdfU | (scratch << 8U)));
        code_.push_back(static_cast<std::uint16_t>(
            scratch | (static_cast<std::uint8_t>(state >> 32U) << 8U)));
        code_.push_back(static_cast<std::uint16_t>(0xd8U | (scratch << 8U)));
        code_.push_back(static_cast<std::uint16_t>(
            scratch | (static_cast<std::uint8_t>(state >> 48U) << 8U)));
        code_.push_back(static_cast<std::uint16_t>(
            0xdaU | (scratch << 8U)));
        code_.push_back(static_cast<std::uint16_t>(
            scratch | (static_cast<std::uint16_t>(0x5dU) << 8U)));
        code_.push_back(static_cast<std::uint16_t>(
            0xdfU | (scratch << 8U)));
        code_.push_back(static_cast<std::uint16_t>(
            scratch | (static_cast<std::uint16_t>(0xa7U) << 8U)));
        code_.push_back(static_cast<std::uint16_t>(
            0x38U | (scratch << 8U))); // secondary false-arm split
        code_.push_back(4U);
        code_.push_back(static_cast<std::uint16_t>(
            0xdfU | (scratch << 8U)));
        code_.push_back(static_cast<std::uint16_t>(
            scratch | (static_cast<std::uint16_t>(0x63U) << 8U)));
        added_blocks_ += 4U;
        return true;
    }

bool PrefixAssembler::AppendDataBarrier(std::uint16_t scratch,
                                         std::uint64_t state) {
        if (scratch > 0x0fU || !Reserve(8U)) return false;
        const auto first = static_cast<std::uint16_t>(state);
        const auto second = static_cast<std::uint16_t>(state >> 17U);
        const auto third = static_cast<std::uint16_t>(state >> 41U);
        code_.push_back(static_cast<std::uint16_t>(0x13U | (scratch << 8U)));
        code_.push_back(first);
        code_.push_back(static_cast<std::uint16_t>(
            0xd7U | (scratch << 8U) | (scratch << 12U)));
        code_.push_back(second == 0U ? 0x6d2bU : second);
        code_.push_back(static_cast<std::uint16_t>(
            0xd0U | (scratch << 8U) | (scratch << 12U)));
        code_.push_back(third == 0U ? 0x39a7U : third);
        code_.push_back(static_cast<std::uint16_t>(
            0xd7U | (scratch << 8U) | (scratch << 12U)));
        code_.push_back(static_cast<std::uint16_t>(first ^ second ^ third));
        return true;
    }

bool PrefixAssembler::AppendMixedDispatch(std::uint16_t predicate,
                                           std::uint16_t scratch) {
        if (!Reserve(44U, 10U)) return false;
        return AppendOpaqueBranch(predicate, false) &&
               AppendSwitch(scratch, false) && AppendSwitch(scratch, true);
    }

bool PrefixAssembler::AppendSsaPollution(std::uint16_t predicate,
                                          std::uint16_t first,
                                          std::uint16_t second,
                                          std::uint64_t state) {
        if (predicate > 0xffU || first > 0xffU || second > 0xffU ||
            first == second || predicate == first || predicate == second ||
            !Reserve(16U, 4U)) {
            return false;
        }
        const auto left = static_cast<std::uint16_t>(state | 1U);
        const auto right = static_cast<std::uint16_t>((state >> 21U) | 1U);
        code_.push_back(static_cast<std::uint16_t>(0x38U | (predicate << 8U)));
        code_.push_back(6U);
        code_.push_back(static_cast<std::uint16_t>(0x13U | (first << 8U)));
        code_.push_back(left);
        code_.push_back(0x0029U);
        code_.push_back(4U);
        code_.push_back(static_cast<std::uint16_t>(0x13U | (first << 8U)));
        code_.push_back(right);
        code_.push_back(static_cast<std::uint16_t>(0x13U | (second << 8U)));
        code_.push_back(static_cast<std::uint16_t>(left ^ right));
        code_.push_back(static_cast<std::uint16_t>(
            0x90U | (first << 8U)));
        code_.push_back(static_cast<std::uint16_t>(first | (second << 8U)));
        code_.push_back(static_cast<std::uint16_t>(0xdfU | (second << 8U)));
        code_.push_back(static_cast<std::uint16_t>(first | 0x5d00U));
        code_.push_back(static_cast<std::uint16_t>(0xd8U | (first << 8U)));
        code_.push_back(static_cast<std::uint16_t>(first |
            (static_cast<std::uint8_t>(right) << 8U)));
        added_blocks_ += 4U;
        return true;
    }

bool PrefixAssembler::AppendDataflowPollution(std::uint16_t first,
                                               std::uint16_t second,
                                               std::uint64_t state) {
        if (first > 0x0fU || second > 0x0fU || first == second ||
            !Reserve(20U, 1U)) {
            return false;
        }
        const auto a = static_cast<std::uint16_t>(state | 1U);
        const auto b = static_cast<std::uint16_t>((state >> 23U) | 1U);
        code_.insert(code_.end(), {
            static_cast<std::uint16_t>(0x13U | (first << 8U)), a,
            static_cast<std::uint16_t>(0x13U | (second << 8U)), b,
        });
        for (std::uint32_t round = 0U; round < 7U; ++round) {
            const auto opcode = static_cast<std::uint16_t>(
                (round % 3U) == 0U ? 0xb7U :
                (round % 3U) == 1U ? 0xb0U : 0xb2U);
            code_.push_back(static_cast<std::uint16_t>(
                opcode | (first << 8U) | (second << 12U)));
            code_.push_back(static_cast<std::uint16_t>(
                0x01U | (second << 8U) | (first << 12U)));
        }
        code_.push_back(static_cast<std::uint16_t>(0xd7U | (first << 8U) |
                                                   (first << 12U)));
        code_.push_back(static_cast<std::uint16_t>(a ^ b));
        ++added_blocks_;
        return true;
    }

bool PrefixAssembler::AppendRegisterShape(std::uint16_t first,
                                           std::uint16_t second,
                                           std::uint64_t state) {
        if (first > 0xffU || second > 0xffU || first == second ||
            !Reserve(14U, 1U)) {
            return false;
        }
        const auto literal = static_cast<std::uint16_t>(state | 1U);
        code_.insert(code_.end(), {
            static_cast<std::uint16_t>(0x13U | (first << 8U)), literal,
            static_cast<std::uint16_t>(0x13U | (second << 8U)),
            static_cast<std::uint16_t>(~literal),
            0x0003U, first, second, // move/16 vAAAA, vBBBB
            0x0003U, second, first,
            static_cast<std::uint16_t>(0x02U | (first << 8U)), second,
            static_cast<std::uint16_t>(0x02U | (second << 8U)), first,
        });
        ++added_blocks_;
        return true;
    }

bool PrefixAssembler::AppendMultiState(std::uint16_t first, std::uint16_t second) {
        if (first > 0x0fU || second > 0x0fU || !Reserve(5U, 2U)) return false;
        code_.push_back(static_cast<std::uint16_t>(0x0012U | (first << 8U)));
        code_.push_back(static_cast<std::uint16_t>(0x1012U | (second << 8U)));
        code_.push_back(static_cast<std::uint16_t>(
            0xb7U | (first << 8U) | (second << 12U))); // xor-int/2addr
        code_.push_back(static_cast<std::uint16_t>(
            0x32U | (first << 8U) | (second << 12U))); // if-eq
        code_.push_back(2U);
        added_blocks_ += 2U;
        return true;
    }

bool PrefixAssembler::AppendExceptionDispatch(std::uint16_t scratch,
                                               std::uint16_t helper_method,
                                               std::uint64_t state) {
        if (scratch > 0x0fU || tries_.size() >= try_limit_ ||
            !Reserve(17U, 2U)) {
            return false;
        }
        const auto start = static_cast<std::uint32_t>(code_.size());
        const auto first = static_cast<std::uint8_t>(state | 1U);
        const auto second = static_cast<std::uint8_t>((state >> 29U) | 1U);
        const auto third = static_cast<std::uint8_t>((state >> 47U) | 1U);
        code_.insert(code_.end(), {
            0x0071U, helper_method, 0U, // try: invoke-static {}, helper()I
            static_cast<std::uint16_t>(0x0aU | (scratch << 8U)),
            static_cast<std::uint16_t>(0xdfU | (scratch << 8U)),
            static_cast<std::uint16_t>(scratch | (first << 8U)),
            static_cast<std::uint16_t>(0x12U | (scratch << 8U)),
            static_cast<std::uint16_t>(0x27U | (scratch << 8U)),
            static_cast<std::uint16_t>(0x0dU | (scratch << 8U)),
            0x0071U, helper_method, 0U, // catch: invoke-static {}, helper()I
            static_cast<std::uint16_t>(0x0aU | (scratch << 8U)),
            static_cast<std::uint16_t>(0xdfU | (scratch << 8U)),
            static_cast<std::uint16_t>(scratch | (second << 8U)),
            static_cast<std::uint16_t>(0xd8U | (scratch << 8U)),
            static_cast<std::uint16_t>(scratch | (third << 8U)),
        });
        tries_.push_back({start, 8U, {{std::nullopt, start + 8U}}});
        added_blocks_ += 2U;
        return true;
    }

bool PrefixAssembler::AppendExceptionMaze(std::uint16_t scratch,
                                           std::uint16_t helper_method,
                                           std::uint64_t state) {
        if (try_limit_ - std::min(try_limit_, tries_.size()) < 2U ||
            !Reserve(34U, 4U)) {
            return false;
        }
        return AppendExceptionDispatch(scratch, helper_method, state) &&
               AppendExceptionDispatch(scratch, helper_method,
                                       state ^ 0x9e3779b97f4a7c15ULL);
    }

bool PrefixAssembler::AppendSequentialExceptionMaze(
        std::uint16_t scratch, std::uint16_t helper_method,
        std::uint64_t state) {
        const auto alignment = (code_.size() & 1U) != 0U ? 3U : 0U;
        if (try_limit_ - std::min(try_limit_, tries_.size()) < 2U ||
            !Reserve(51U + alignment, 8U)) {
            return false;
        }
        return AppendSwitch(scratch, true) &&
               AppendExceptionMaze(scratch, helper_method, state);
    }

bool PrefixAssembler::AppendSharedHandlerFanIn(std::uint16_t predicate,
                                                 std::uint16_t scratch,
                                                 std::uint16_t helper_method,
                                                 std::uint64_t state) {
        if (predicate > 0xffU || scratch > 0x0fU || predicate == scratch ||
            try_limit_ - std::min(try_limit_, tries_.size()) < 2U ||
            !Reserve(27U, 4U)) {
            return false;
        }
        const auto start = static_cast<std::uint32_t>(code_.size());
        const auto first = static_cast<std::uint8_t>(state | 1U);
        const auto second = static_cast<std::uint8_t>((state >> 23U) | 1U);
        const auto third = static_cast<std::uint8_t>((state >> 47U) | 1U);
        code_.insert(code_.end(), {
            static_cast<std::uint16_t>(0x38U | (predicate << 8U)), 10U,
            0x0071U, helper_method, 0U,
            static_cast<std::uint16_t>(0x0aU | (scratch << 8U)),
            static_cast<std::uint16_t>(0xdfU | (scratch << 8U)),
            static_cast<std::uint16_t>(scratch | (first << 8U)),
            static_cast<std::uint16_t>(0x12U | (scratch << 8U)),
            static_cast<std::uint16_t>(0x27U | (scratch << 8U)),
            0x0071U, helper_method, 0U,
            static_cast<std::uint16_t>(0x0aU | (scratch << 8U)),
            static_cast<std::uint16_t>(0xdfU | (scratch << 8U)),
            static_cast<std::uint16_t>(scratch | (second << 8U)),
            static_cast<std::uint16_t>(0x12U | (scratch << 8U)),
            static_cast<std::uint16_t>(0x27U | (scratch << 8U)),
            static_cast<std::uint16_t>(0x0dU | (scratch << 8U)),
            0x0071U, helper_method, 0U,
            static_cast<std::uint16_t>(0x0aU | (scratch << 8U)),
            static_cast<std::uint16_t>(0xdfU | (scratch << 8U)),
            static_cast<std::uint16_t>(scratch | (third << 8U)),
        });
        tries_.push_back({start + 2U, 8U,
                          {{std::nullopt, start + 18U}}});
        tries_.push_back({start + 10U, 8U,
                          {{std::nullopt, start + 18U}}});
        added_blocks_ += 4U;
        return true;
    }

bool PrefixAssembler::AppendDecompilerMaze(std::uint16_t predicate,
                                             std::uint16_t scratch,
                                             std::uint16_t helper_method,
                                             std::uint64_t state) {
        if (!Reserve(61U, 12U)) return false;
        return AppendMixedDispatch(predicate, scratch) &&
               AppendExceptionDispatch(scratch, helper_method, state);
    }

void PrefixAssembler::EnableBlockReordering(std::uint64_t seed) noexcept {
        reorder_blocks_ = true;
        reorder_seed_ ^= seed + 0x9e3779b97f4a7c15ULL +
                         (reorder_seed_ << 6U) + (reorder_seed_ >> 2U);
    }

bool PrefixAssembler::ReplaceInstruction(
        std::uint32_t offset, std::uint32_t original_width,
        std::vector<std::uint16_t> replacement) {
        if (replacement.empty() || replacement.size() < original_width) return false;
        const auto growth = replacement.size() - original_width;
        if (!Reserve(growth) || replacements_.contains(offset)) return false;
        replacement_growth_ += growth;
        replacements_.emplace(offset, std::move(replacement));
        return true;
    }

bool PrefixAssembler::empty() const noexcept {
        return code_.empty() && !reorder_blocks_ && replacements_.empty();
    }

std::size_t PrefixAssembler::added_blocks() const noexcept {
        return added_blocks_;
    }

std::size_t PrefixAssembler::remaining_blocks() const noexcept {
        return block_limit_ - std::min(block_limit_, added_blocks_);
    }

dex::CodePrefix PrefixAssembler::Finish(std::uint32_t code_off) && {
        dex::CodePrefix result;
        result.code_off = code_off;
        result.code_units = std::move(code_);
        result.try_regions = std::move(tries_);
        result.reorder_blocks = reorder_blocks_;
        result.reorder_seed = reorder_seed_;
        result.linear_replacements = std::move(replacements_);
        return result;
    }

bool PrefixAssembler::Reserve(std::size_t width,
                               std::size_t blocks) const noexcept {
        const auto used = code_.size() + replacement_growth_;
        return width <= limit_ - std::min(limit_, used) &&
               blocks <= block_limit_ - std::min(block_limit_, added_blocks_);
    }

bool PrefixAssembler::AppendSwitch(std::uint16_t scratch, bool sparse) {
        const auto alignment = (code_.size() & 1U) != 0U ? 3U : 0U;
        if (scratch > 0xffU || !Reserve(17U + alignment, 4U)) return false;
        if (alignment != 0U) {
            code_.insert(code_.end(), {
                static_cast<std::uint16_t>(0x14U | (scratch << 8U)), 0U, 0U});
        }
        code_.push_back(static_cast<std::uint16_t>(
            0x13U | (scratch << 8U)));
        code_.push_back(sparse ? 1U : 0U);
        code_.push_back(static_cast<std::uint16_t>(
            (sparse ? 0x2cU : 0x2bU) | (scratch << 8U)));
        code_.push_back(9U);
        code_.push_back(0U);
        code_.push_back(0x0029U);
        code_.push_back(12U);
        code_.push_back(static_cast<std::uint16_t>(0xdfU | (scratch << 8U)));
        code_.push_back(static_cast<std::uint16_t>(scratch | 0x0100U));
        code_.push_back(0x0029U);
        code_.push_back(8U);
        code_.push_back(sparse ? 0x0200U : 0x0100U);
        code_.push_back(1U);
        code_.push_back(sparse ? 1U : 0U);
        code_.push_back(0U);
        code_.push_back(5U);
        code_.push_back(0U);
        added_blocks_ += 4U;
        return true;
    }

} // namespace birch::guard::detail
