#pragma once

#include "birch/dex/builder.h"
#include "birch/guard/model_lowering.h"

#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>

namespace birch::guard::detail {

inline constexpr std::uint32_t kStatic = 0x0008U;
inline constexpr std::uint32_t kNative = 0x0100U;
inline constexpr std::uint32_t kAbstract = 0x0400U;
inline constexpr std::uint32_t kPrivate = 0x0002U;
inline constexpr std::uint32_t kSynthetic = 0x1000U;
inline constexpr std::uint32_t kInterface = 0x0200U;
inline constexpr std::uint32_t kEnum = 0x4000U;

struct ReturnSequence {
    std::vector<std::uint16_t> code;
    std::uint16_t local_words{};
};


ReturnSequence BuildReturnSequence(std::string_view return_type);

std::uint16_t TypeWordCount(std::string_view type);

void ValidateInvokeRegisters(
    std::uint8_t opcode, const std::vector<std::uint16_t>& registers,
    const dex::MethodReference& reference);

void AppendInvoke35c(std::vector<std::uint16_t>& code, std::uint8_t opcode,
                     const std::vector<std::uint16_t>& registers,
                     dex::MethodBodySpec& body,
                     dex::MethodReference reference);

void AppendInvoke(std::vector<std::uint16_t>& code, std::uint8_t opcode,
                  const std::vector<std::uint16_t>& registers,
                  dex::MethodBodySpec& body,
                  dex::MethodReference reference);

dex::MethodBodySpec BuildStaticForwardBody(
    std::string_view return_type, std::uint16_t input_words,
    dex::MethodReference target);

std::vector<std::uint16_t> InputRegisters(std::uint16_t base,
                                          std::uint16_t count);

std::string SyntheticName(std::uint64_t seed, std::string_view role,
                          std::size_t ordinal,
                          const std::set<std::string, std::less<>>& used);

std::string ReflectionProxyName(
    std::uint64_t seed, std::size_t ordinal,
    const std::set<std::string, std::less<>>& used);

dex::MethodReference MethodReferenceFor(const dex::ClassSpec& klass,
                                        const dex::MethodSpec& method);

dex::MethodBodySpec BuildWrapperBody(const dex::ClassSpec& klass,
                                     const dex::MethodSpec& original,
                                     const dex::MethodSpec& target,
                                     std::optional<std::uint8_t> depth,
                                     std::optional<std::string_view> target_owner =
                                         std::nullopt);

bool HasTransformableBody(const dex::MethodSpec& method);

std::size_t BodyInstructionWidth(const dex::MethodBodySpec& body,
                                 std::size_t cursor);

bool HasInvokeSuper(const dex::MethodSpec& method);

bool Selected(const PassConfig& pass, std::uint64_t global_seed,
              std::string_view key, std::uint64_t salt);

std::string SyntheticClassDescriptor(
    std::string_view role, std::string_view source, std::uint64_t seed,
    std::size_t ordinal, const std::set<std::string, std::less<>>& used);

std::string MethodIdentity(const dex::MethodReference& reference);

std::vector<std::uint16_t> ModelInvokeRegisters(
    const dex::MethodBodySpec& body, std::uint32_t instruction_offset);

std::vector<std::uint8_t> CompactDex(const dex::DexFile& source);

} // namespace birch::guard::detail
