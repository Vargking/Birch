#include "birch/guard/model_lowering.h"

#include "birch/dex/builder.h"
#include "birch/dex/code.h"
#include "birch/dex/cloner.h"
#include "birch/dex/remap.h"
#include "birch/dex/verifier.h"
#include "birch/guard/scope.h"
#include "birch/guard/constant_runtime.h"
#include "birch/guard/opaque_runtime.h"
#include "birch/guard/string_runtime.h"
#include "birch/utils/hash.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <map>
#include <span>
#include <iterator>
#include <type_traits>
#include <utility>

#include "model_strings.h"
#include "model_support.h"

namespace birch::guard::detail {
namespace {

std::vector<std::uint16_t> DecodeMutf8Units(std::string_view value) {
    std::vector<std::uint16_t> result;
    for (std::size_t cursor = 0U; cursor < value.size();) {
        const auto first = static_cast<std::uint8_t>(value[cursor]);
        if (first == 0xc0U && cursor + 1U < value.size() &&
            static_cast<std::uint8_t>(value[cursor + 1U]) == 0x80U) {
            result.push_back(0U);
            cursor += 2U;
        } else if (first <= 0x7fU) {
            result.push_back(first);
            ++cursor;
        } else if (first >= 0xc0U && first <= 0xdfU &&
                   cursor + 1U < value.size()) {
            result.push_back(static_cast<std::uint16_t>(
                ((first & 0x1fU) << 6U) |
                (static_cast<std::uint8_t>(value[cursor + 1U]) & 0x3fU)));
            cursor += 2U;
        } else if (first >= 0xe0U && first <= 0xefU &&
                   cursor + 2U < value.size()) {
            result.push_back(static_cast<std::uint16_t>(
                ((first & 0x0fU) << 12U) |
                ((static_cast<std::uint8_t>(value[cursor + 1U]) & 0x3fU) << 6U) |
                (static_cast<std::uint8_t>(value[cursor + 2U]) & 0x3fU)));
            cursor += 3U;
        } else {
            throw std::invalid_argument("invalid MUTF-8 string while encrypting DEX");
        }
    }
    return result;
}


std::string EncodeMutf8Units(std::span<const std::uint16_t> units) {
    std::string result;
    for (const auto unit : units) {
        if (unit == 0U) {
            result.append("\xc0\x80", 2U);
        } else if (unit <= 0x7fU) {
            result.push_back(static_cast<char>(unit));
        } else if (unit <= 0x7ffU) {
            result.push_back(static_cast<char>(0xc0U | (unit >> 6U)));
            result.push_back(static_cast<char>(0x80U | (unit & 0x3fU)));
        } else {
            result.push_back(static_cast<char>(0xe0U | (unit >> 12U)));
            result.push_back(static_cast<char>(0x80U | ((unit >> 6U) & 0x3fU)));
            result.push_back(static_cast<char>(0x80U | (unit & 0x3fU)));
        }
    }
    return result;
}


std::string StringHelperDescriptor(
    const std::set<std::string, std::less<>>& descriptors,
    std::uint64_t seed) {
    return SyntheticClassDescriptor("string-runtime", "data", seed, 0U, descriptors);
}

enum class StringCipherMode : std::uint8_t {
    XorCascade,
    AddXorCascade,
    IndexMixed,
    DualRound,
};


struct StringCipherKeys {
    StringCipherMode mode{};
    std::uint16_t first{};
    std::uint16_t second{};
    std::uint16_t third{};
};


StringCipherKeys StringKeys(std::string_view value, std::uint64_t seed) {
    auto state = utils::StableHash64(value, seed);
    const auto mode = static_cast<StringCipherMode>(state % 4U);
    state ^= state >> 29U;
    const auto next = [&]() {
        state ^= state << 13U;
        state ^= state >> 7U;
        state ^= state << 17U;
        auto result = static_cast<std::uint16_t>(state);
        if (result == 0U) result = 0x5a5bU;
        return result;
    };
    return {mode, next(), next(), next()};
}


std::uint16_t EncryptStringUnit(std::uint16_t value, std::uint16_t index,
                                const StringCipherKeys& keys) {
    auto result = static_cast<std::uint32_t>(value);
    switch (keys.mode) {
        case StringCipherMode::XorCascade:
            result ^= keys.first;
            result += keys.second;
            result ^= keys.third;
            break;
        case StringCipherMode::AddXorCascade:
            result += keys.first;
            result ^= keys.second;
            result += keys.third;
            break;
        case StringCipherMode::IndexMixed:
            result ^= keys.first;
            result ^= index;
            result += keys.second;
            result ^= keys.third;
            break;
        case StringCipherMode::DualRound:
            result += keys.first;
            result ^= keys.second;
            result += keys.third;
            result ^= keys.first;
            break;
    }
    for (std::uint32_t round = 0U; round < 8U; ++round) {
        const auto add_key = static_cast<std::uint16_t>(
            keys.first + round * 0x1357U);
        const auto xor_key = static_cast<std::uint16_t>(
            keys.second ^ (keys.third + round * 0x246dU));
        result ^= static_cast<std::uint16_t>(index + round * 17U);
        result += add_key;
        result ^= xor_key;
        result &= 0xffffU;
    }
    return static_cast<std::uint16_t>(result);
}


void AppendStringCipherInverse(std::vector<std::uint16_t>& code,
                               std::uint16_t index_register,
                               std::uint16_t value_register,
                               const StringCipherKeys& keys) {
    const auto split_mask = [&](std::uint16_t literal,
                                std::uint16_t salt) {
        auto first = static_cast<std::uint16_t>(
            utils::StableHash64(std::to_string(literal),
                                static_cast<std::uint64_t>(keys.first) << 32U ^
                                static_cast<std::uint64_t>(keys.second) << 16U ^
                                keys.third ^ salt));
        if (first == 0U || first == literal) {
            first = static_cast<std::uint16_t>(first ^ 0x5a5bU ^ salt);
        }
        return std::array<std::uint16_t, 2U>{
            first, static_cast<std::uint16_t>(literal ^ first)};
    };
    const auto split_sum = [&](std::uint16_t literal,
                               std::uint16_t salt) {
        auto first = static_cast<std::uint16_t>(
            utils::StableHash64(std::to_string(literal),
                                static_cast<std::uint64_t>(keys.third) << 32U ^
                                static_cast<std::uint64_t>(keys.second) << 16U ^
                                keys.first ^ salt));
        if (first == 0U || first == literal) {
            first = static_cast<std::uint16_t>(first + 0x33c5U + salt);
        }
        return std::array<std::uint16_t, 2U>{
            first, static_cast<std::uint16_t>(literal - first)};
    };
    const auto append_xor = [&](std::uint16_t literal) {
        for (const auto part : split_mask(literal,
                                          static_cast<std::uint16_t>(code.size()))) {
            code.push_back(static_cast<std::uint16_t>(
                0xd7U | (value_register << 8U) | (value_register << 12U)));
            code.push_back(part);
        }
    };
    const auto append_add = [&](std::int32_t literal) {
        for (const auto part : split_sum(static_cast<std::uint16_t>(literal),
                                         static_cast<std::uint16_t>(code.size()))) {
            code.push_back(static_cast<std::uint16_t>(
                0xd0U | (value_register << 8U) | (value_register << 12U)));
            code.push_back(part);
        }
    };
    for (std::uint32_t reverse = 8U; reverse != 0U; --reverse) {
        const auto round = reverse - 1U;
        const auto add_key = static_cast<std::uint16_t>(
            keys.first + round * 0x1357U);
        const auto xor_key = static_cast<std::uint16_t>(
            keys.second ^ (keys.third + round * 0x246dU));
        append_xor(xor_key);
        append_add(-static_cast<std::int32_t>(add_key));
        code.push_back(0x0413U); // const/16 v4, round index salt
        code.push_back(static_cast<std::uint16_t>(round * 17U));
        code.push_back(static_cast<std::uint16_t>(
            0xb0U | (4U << 8U) | (index_register << 12U)));
        code.push_back(static_cast<std::uint16_t>(
            0xb7U | (value_register << 8U) | (4U << 12U)));
    }
    switch (keys.mode) {
        case StringCipherMode::XorCascade:
            append_xor(keys.third);
            append_add(-static_cast<std::int32_t>(keys.second));
            append_xor(keys.first);
            break;
        case StringCipherMode::AddXorCascade:
            append_add(-static_cast<std::int32_t>(keys.third));
            append_xor(keys.second);
            append_add(-static_cast<std::int32_t>(keys.first));
            break;
        case StringCipherMode::IndexMixed:
            append_xor(keys.third);
            append_add(-static_cast<std::int32_t>(keys.second));
            code.push_back(static_cast<std::uint16_t>(
                0xb7U | (value_register << 8U) | (index_register << 12U)));
            append_xor(keys.first);
            break;
        case StringCipherMode::DualRound:
            append_xor(keys.first);
            append_add(-static_cast<std::int32_t>(keys.third));
            append_xor(keys.second);
            append_add(-static_cast<std::int32_t>(keys.first));
            break;
    }
}


dex::MethodSpec BuildStringChunkHelper(std::string_view method_name,
                                        std::string_view value,
                                        std::uint64_t seed, bool intern_result) {
    const auto keys = StringKeys(value, seed);
    auto units = DecodeMutf8Units(value);
    for (std::uint32_t index = 0U; index < units.size(); ++index) {
        units[index] = EncryptStringUnit(units[index],
                                         static_cast<std::uint16_t>(index), keys);
    }
    dex::MethodSpec method;
    method.name = std::string(method_name);
    method.return_type = "Ljava/lang/String;";
    method.access_flags = 0x1009U;
    method.body.registers_size = 8U;
    method.body.outs_size = 2U;
    auto& code = method.body.code_units;
    const auto add_reference = [&](dex::MethodBodySpec::SymbolicReference reference,
                                   std::uint32_t at, bool wide = false) {
        method.body.references.push_back({std::move(reference), at, wide});
    };

    const auto append_length_constant = [&](std::uint32_t length) {
        if (length <= 0x7fffU) {
            code.push_back(0x0313U); // const/16 v3, length
            code.push_back(static_cast<std::uint16_t>(length));
            return;
        }
        code.push_back(0x0314U); // const v3, length
        code.push_back(static_cast<std::uint16_t>(length & 0xffffU));
        code.push_back(static_cast<std::uint16_t>(length >> 16U));
    };

    std::vector<std::uint8_t> encrypted_bytes;
    encrypted_bytes.reserve(units.size() * 2U);
    for (const auto unit : units) {
        encrypted_bytes.push_back(static_cast<std::uint8_t>(unit & 0xffU));
        encrypted_bytes.push_back(static_cast<std::uint8_t>(unit >> 8U));
    }

    append_length_constant(static_cast<std::uint32_t>(encrypted_bytes.size()));
    code.push_back(0x3123U); // new-array v1, v3, byte[]
    code.push_back(0U);
    add_reference(dex::TypeReference{"[B"}, static_cast<std::uint32_t>(code.size() - 1U));
    const auto fill_offset = static_cast<std::uint32_t>(code.size());
    code.push_back(0x0126U); // fill-array-data v1, payload
    code.push_back(0U);
    code.push_back(0U);
    append_length_constant(static_cast<std::uint32_t>(units.size()));
    code.push_back(0x3223U); // new-array v2, v3, char[]
    code.push_back(0U);
    add_reference(dex::TypeReference{"[C"}, static_cast<std::uint32_t>(code.size() - 1U));
    code.push_back(0x0312U); // const/4 v3, #0
    const auto loop_offset = static_cast<std::uint32_t>(code.size());
    code.push_back(0x2421U); // array-length v4, v2
    const auto if_offset = static_cast<std::uint32_t>(code.size());
    code.push_back(0x4335U); // if-ge v3, v4, new String (0x37 is if-le)
    code.push_back(0U);
    code.push_back(0x05daU); // mul-int/lit8 v5, v3, #2
    code.push_back(0x0203U);
    code.push_back(0x0648U); // aget-byte v6, v1, v5
    code.push_back(0x0501U);
    code.push_back(0x66d5U); // and-int/lit16 v6, v6, #0xff
    code.push_back(0x00ffU);
    code.push_back(0x05d8U); // add-int/lit8 v5, v5, #1
    code.push_back(0x0105U);
    code.push_back(0x0748U); // aget-byte v7, v1, v5
    code.push_back(0x0501U);
    code.push_back(0x77d5U); // and-int/lit16 v7, v7, #0xff
    code.push_back(0x00ffU);
    code.push_back(0x07e0U); // shl-int/lit8 v7, v7, #8
    code.push_back(0x0807U);
    code.push_back(0x76b6U); // or-int/2addr v6, v7
    code.push_back(0x0712U); // const/4 v7, #0
    code.push_back(0x074fU); // aput-byte v7, v1, v5
    code.push_back(0x0501U);
    code.push_back(0x05d8U); // add-int/lit8 v5, v5, #-1
    code.push_back(0xff05U);
    code.push_back(0x074fU); // aput-byte v7, v1, v5
    code.push_back(0x0501U);
    AppendStringCipherInverse(code, 3U, 6U, keys);
    code.push_back(0x668eU); // int-to-char v6, v6
    code.push_back(0x0650U); // aput-char v6, v2, v3
    code.push_back(0x0302U);
    code.push_back(0x03d8U); // add-int/lit8 v3, v3, #1
    code.push_back(0x0103U);
    const auto goto_offset = static_cast<std::uint32_t>(code.size());
    code.push_back(0x0029U);
    code.push_back(0U);
    const auto new_string_offset = static_cast<std::uint32_t>(code.size());
    code[if_offset + 1U] = static_cast<std::uint16_t>(
        new_string_offset - if_offset);
    code.push_back(0x0022U); // new-instance v0, String
    code.push_back(0U);
    add_reference(dex::TypeReference{"Ljava/lang/String;"},
                  new_string_offset + 1U);
    code.push_back(0x2070U); // invoke-direct {v0, v2}, String.<init>
    code.push_back(0U);
    code.push_back(0x0020U);
    add_reference(dex::MethodReference{"Ljava/lang/String;", "<init>", "V",
                                       {"[C"}}, new_string_offset + 3U);
    // String(char[]) copies the input on Android. Destroy the transient
    // plaintext characters before returning the immutable String instance.
    code.push_back(0x0312U); // const/4 v3, #0
    const auto wipe_loop_offset = static_cast<std::uint32_t>(code.size());
    code.push_back(0x2421U); // array-length v4, v2
    const auto wipe_done_branch = static_cast<std::uint32_t>(code.size());
    code.insert(code.end(), {0x4335U, 0U}); // if-ge v3, v4, return
    code.push_back(0x0612U); // const/4 v6, #0
    code.push_back(0x0650U); // aput-char v6, v2, v3
    code.push_back(0x0302U);
    code.push_back(0x03d8U); // add-int/lit8 v3, v3, #1
    code.push_back(0x0103U);
    const auto wipe_goto_offset = static_cast<std::uint32_t>(code.size());
    code.insert(code.end(), {0x0029U, 0U}); // goto/16 wipe loop
    const auto return_object_offset = static_cast<std::uint32_t>(code.size());
    if (intern_result) {
        // const-string returns the canonical literal, not a fresh allocation.
        // Only complete literals are interned, never private split fragments.
        AppendInvoke35c(code, 0x6eU, {0U}, method.body,
                        {"Ljava/lang/String;", "intern", "Ljava/lang/String;", {}});
        code.push_back(0x000cU); // move-result-object v0
    }
    code.push_back(0x0011U); // return-object v0
    code[wipe_done_branch + 1U] = static_cast<std::uint16_t>(
        return_object_offset - wipe_done_branch);
    code[wipe_goto_offset + 1U] = static_cast<std::uint16_t>(
        static_cast<std::int32_t>(wipe_loop_offset) -
        static_cast<std::int32_t>(wipe_goto_offset));
    code[goto_offset + 1U] = static_cast<std::uint16_t>(
        static_cast<std::int32_t>(loop_offset) -
        static_cast<std::int32_t>(goto_offset));
    if ((code.size() & 1U) != 0U) {
        // ART verifies this unreachable tail with undefined inputs. const
        // changes parity while defining its destination instead of reading it.
        code.insert(code.end(), {0x0314U, 0U, 0U}); // const v3, #0
    }
    const auto payload_offset = static_cast<std::uint32_t>(code.size());
    const auto relative_payload = static_cast<std::int32_t>(payload_offset) -
                                  static_cast<std::int32_t>(fill_offset);
    code[fill_offset + 1U] = static_cast<std::uint16_t>(
        relative_payload & 0xffff);
    code[fill_offset + 2U] = static_cast<std::uint16_t>(
        (static_cast<std::uint32_t>(relative_payload) >> 16U) & 0xffffU);
    code.push_back(0x0300U);
    code.push_back(1U);
    code.push_back(static_cast<std::uint16_t>(encrypted_bytes.size() & 0xffffU));
    code.push_back(static_cast<std::uint16_t>(
        (static_cast<std::uint32_t>(encrypted_bytes.size()) >> 16U) & 0xffffU));
    for (std::size_t cursor = 0U; cursor < encrypted_bytes.size(); cursor += 2U) {
        const auto low = encrypted_bytes[cursor];
        const auto high = cursor + 1U < encrypted_bytes.size() ?
            encrypted_bytes[cursor + 1U] : 0U;
        code.push_back(static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(low) |
            (static_cast<std::uint16_t>(high) << 8U)));
    }
    return method;
}




constexpr std::uint8_t kStringEncryptionSite = 1U << 0U;

constexpr std::uint8_t kStringSplittingSite = 1U << 1U;

constexpr std::uint8_t kReflectionEncryptionSite = 1U << 2U;

constexpr std::uint8_t kEncryptedLoadingSite = 1U << 3U;

constexpr std::uint8_t kIndirectReflectionSite = 1U << 4U;


std::string StringMethodKey(std::string_view owner,
                            const dex::MethodSpec& method) {
    std::string result(owner);
    result += "->";
    result += method.name;
    result += '(';
    for (const auto& parameter : method.parameter_types) result += parameter;
    result += ')';
    result += method.return_type;
    return result;
}


bool StringPassSelected(const PassConfig& pass, std::uint64_t global_seed,
                        std::string_view key, std::uint64_t salt,
                        std::uint32_t& applications) {
    if (!pass.enabled || (pass.max_applications_per_method.has_value() &&
                          applications >= *pass.max_applications_per_method)) {
        return false;
    }
    if (!Selected(pass, global_seed, key, salt)) return false;
    ++applications;
    return true;
}

// Encryption is a coverage guarantee.  Pass intensity controls the cost of
// the generated decoder (splitting, rounds, and helper layout), but it must
// never leave the original literal in a protected method.  Sampling is kept
// for optional structural variants only.

bool StringPassRequired(const PassConfig& pass,
                        std::uint32_t& applications) {
    if (!pass.enabled || (pass.max_applications_per_method.has_value() &&
                          applications >= *pass.max_applications_per_method)) {
        return false;
    }
    ++applications;
    return true;
}


std::uint8_t SensitiveStringUse(const dex::MethodReference& reference,
                                std::span<const std::uint16_t> registers,
                                std::uint16_t string_register) {
    const auto matches = [&](std::size_t ordinal) {
        return ordinal < registers.size() &&
               registers[ordinal] == string_register;
    };
    std::uint8_t result = 0U;
    if (reference.name.starts_with("$br$")) {
        std::size_t word = 0U;
        for (const auto& parameter : reference.parameter_types) {
            if (parameter == "Ljava/lang/String;" && word < registers.size() &&
                registers[word] == string_register) {
                result |= kReflectionEncryptionSite |
                          kIndirectReflectionSite;
            }
            word += TypeWordCount(parameter);
        }
    }
    if (reference.owner == "Ljava/lang/Class;" &&
        reference.name == "forName" && matches(0U)) {
        result |= kReflectionEncryptionSite | kIndirectReflectionSite;
    }
    if (reference.owner == "Ljava/lang/Class;" &&
        (reference.name == "getMethod" ||
         reference.name == "getDeclaredMethod" ||
         reference.name == "getField" ||
         reference.name == "getDeclaredField") && matches(1U)) {
        result |= kReflectionEncryptionSite | kIndirectReflectionSite;
    }
    if (reference.owner == "Ljava/lang/ClassLoader;" &&
        reference.name == "loadClass" && matches(1U)) {
        result |= kReflectionEncryptionSite | kIndirectReflectionSite;
    }
    if (reference.owner == "Ljava/lang/invoke/MethodHandles$Lookup;" &&
        (reference.name == "findVirtual" ||
         reference.name == "findStatic" ||
         reference.name == "findConstructor" ||
         reference.name == "findGetter" ||
         reference.name == "findSetter" ||
         reference.name == "findStaticGetter" ||
         reference.name == "findStaticSetter") && matches(2U)) {
        result |= kReflectionEncryptionSite | kIndirectReflectionSite;
    }
    const auto loader_constructor = reference.name == "<init>" &&
        (reference.owner == "Ldalvik/system/DexClassLoader;" ||
         reference.owner == "Ldalvik/system/PathClassLoader;" ||
         reference.owner == "Ldalvik/system/BaseDexClassLoader;");
    if (loader_constructor && matches(1U)) {
        result |= kEncryptedLoadingSite;
    }
    if (reference.owner == "Ldalvik/system/DexFile;" &&
        ((reference.name == "loadDex" && (matches(0U) || matches(1U))) ||
         (reference.name == "<init>" && matches(1U)))) {
        result |= kEncryptedLoadingSite;
    }
    return result;
}


std::uint8_t ClassifyStringSite(const dex::MethodSpec& method,
                                std::uint32_t string_offset,
                                std::uint16_t string_register) {
    std::uint8_t result = 0U;
    std::uint32_t nearest = std::numeric_limits<std::uint32_t>::max();
    for (const auto& patch : method.body.references) {
        const auto* reference = std::get_if<dex::MethodReference>(
            &patch.reference);
        if (reference == nullptr || patch.code_unit == 0U) continue;
        const auto invoke_offset = patch.code_unit - 1U;
        if (invoke_offset <= string_offset || invoke_offset - string_offset > 32U ||
            invoke_offset > nearest) {
            continue;
        }
        const auto registers = ModelInvokeRegisters(method.body, invoke_offset);
        const auto classified = SensitiveStringUse(
            *reference, registers, string_register);
        if (classified != 0U) {
            nearest = invoke_offset;
            result = classified;
        }
    }
    return result;
}


std::optional<std::uint32_t> FindStringHelperMethod(
    const dex::DexFile& dex_file, std::string_view owner,
    std::string_view method_name) {
    for (std::uint32_t index = 0U; index < dex_file.methods().size(); ++index) {
        const auto& method = dex_file.methods()[index];
        if (dex_file.descriptor(method.class_idx) != owner ||
            dex_file.string(method.name_idx) != method_name ||
            dex_file.proto_key(method.proto_idx) != "()Ljava/lang/String;") {
            continue;
        }
        return index;
    }
    return std::nullopt;
}


std::string ParsedStringMethodKey(const dex::DexFile& dex_file,
                                  const dex::DexMethodId& method) {
    return dex_file.descriptor(method.class_idx) + "->" +
           dex_file.string(method.name_idx) + dex_file.proto_key(method.proto_idx);
}


} // namespace

StringHelperBundle ModelStringProtection::BuildStringHelper(
    const std::set<std::string, std::less<>>& descriptors,
    const std::set<std::string, std::less<>>& values,
    const std::set<std::string, std::less<>>& split_values,
    std::uint64_t descriptor_seed, std::uint64_t method_seed) {
    StringHelperBundle bundle;
    auto used_descriptors = descriptors;
    dex::ClassSpec helper;
    helper.descriptor = StringHelperDescriptor(descriptors, descriptor_seed);
    helper.access_flags = 0x1011U;
    bundle.entry_descriptor = helper.descriptor;
    used_descriptors.insert(helper.descriptor);
    // Split payloads have independent owners and keys. Co-locating them in the
    // entry vault would expose every fragment through one runtime surface.
    std::set<std::string, std::less<>> used_method_names;
    for (const auto& value : values) {
        if (!split_values.contains(value) || DecodeMutf8Units(value).size() < 2U) {
            auto method_name = RuntimeStringMethodName(value, method_seed);
            if (!used_method_names.insert(method_name).second) {
                throw std::runtime_error("string vault method hash collision");
            }
            helper.direct_methods.push_back(BuildStringChunkHelper(
                method_name, value, method_seed, true));
            continue;
        }
        const auto units = DecodeMutf8Units(value);
        const auto split_state = utils::StableHash64(
            value, descriptor_seed ^ method_seed ^ 0x53504c495443484bULL);
        const auto desired_chunks = static_cast<std::size_t>(
            4U + split_state % 5U);
        const auto chunk_count = std::min(units.size(), desired_chunks);
        struct ChunkTarget {
            std::string owner;
            std::string method;
        };
        std::vector<ChunkTarget> targets;
        targets.reserve(chunk_count);
        for (std::size_t chunk = 0U; chunk < chunk_count; ++chunk) {
            const auto begin = units.size() * chunk / chunk_count;
            const auto end = units.size() * (chunk + 1U) / chunk_count;
            const auto chunk_value = EncodeMutf8Units(
                std::span<const std::uint16_t>(units.data() + begin,
                                               end - begin));
            const auto chunk_seed = utils::StableHash64(
                value + ":" + std::to_string(chunk),
                method_seed ^ 0x9e3779b97f4a7c15ULL);
            auto chunk_name = RuntimeStringMethodName(chunk_value, chunk_seed) +
                              "$" + std::to_string(chunk);
            if (!used_method_names.insert(chunk_name).second) {
                throw std::runtime_error("string vault chunk method hash collision");
            }
            dex::ClassSpec chunk_helper;
            chunk_helper.descriptor = StringHelperDescriptor(
                used_descriptors, chunk_seed ^ descriptor_seed);
            chunk_helper.access_flags = 0x1011U;
            used_descriptors.insert(chunk_helper.descriptor);
            chunk_helper.direct_methods.push_back(BuildStringChunkHelper(
                chunk_name, chunk_value, chunk_seed, false));
            targets.push_back({chunk_helper.descriptor, std::move(chunk_name)});
            bundle.classes.push_back(std::move(chunk_helper));
        }
        dex::MethodSpec combined;
        combined.name = RuntimeStringMethodName(value, method_seed);
        if (!used_method_names.insert(combined.name).second) {
            throw std::runtime_error("string vault combined method hash collision");
        }
        combined.return_type = "Ljava/lang/String;";
        combined.access_flags = 0x1009U;
        combined.body.registers_size = 2U;
        combined.body.outs_size = 2U;
        for (std::size_t chunk = 0U; chunk < targets.size(); ++chunk) {
            AppendInvoke35c(combined.body.code_units, 0x71U, {}, combined.body,
                            {targets[chunk].owner, targets[chunk].method,
                             "Ljava/lang/String;", {}});
            combined.body.code_units.push_back(static_cast<std::uint16_t>(
                0x0cU | ((chunk == 0U ? 0U : 1U) << 8U)));
            if (chunk == 0U) continue;
            AppendInvoke35c(combined.body.code_units, 0x6eU, {0U, 1U},
                            combined.body,
                            {"Ljava/lang/String;", "concat",
                             "Ljava/lang/String;", {"Ljava/lang/String;"}});
            combined.body.code_units.push_back(0x000cU); // move-result-object v0
        }
        AppendInvoke35c(combined.body.code_units, 0x6eU, {0U}, combined.body,
                        {"Ljava/lang/String;", "intern", "Ljava/lang/String;", {}});
        combined.body.code_units.push_back(0x000cU); // move-result-object v0
        combined.body.code_units.push_back(0x0011U); // return-object v0
        helper.direct_methods.push_back(std::move(combined));
    }
    bundle.classes.push_back(std::move(helper));
    return bundle;
}




void ModelStringProtection::CollectStringValues(const dex::ClassSpec& klass, const GuardConfig& config,
                         StringRewritePlan& plan) {
    const auto& encryption = config.passes.at("data.string_encryption");
    const auto& splitting = config.passes.at("data.string_splitting");
    const auto& reflection = config.passes.at("data.reflection_string_encryption");
    const auto& loading = config.passes.at("loading.encrypted_paths");
    const auto& indirect = config.passes.at("reflection.indirect_targets");
    if (!encryption.enabled && !splitting.enabled && !reflection.enabled &&
        !loading.enabled && !indirect.enabled) return;
    // Static string values live in the encoded static_values array and would
    // otherwise remain plaintext even when every const-string instruction is
    // rewritten.  Put them in the same vault plan so class initialization can
    // materialize them through the encrypted helper method.
    if (encryption.enabled || splitting.enabled) {
        for (const auto& field : klass.static_fields) {
            if (!field.static_value.has_value()) continue;
            if (const auto* value = std::get_if<dex::StringReference>(
                    &field.static_value->value)) {
                plan.values.insert(value->value);
                if (splitting.enabled && value->value.size() >= 2U) {
                    plan.split_values.insert(value->value);
                }
            }
        }
    }
    for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (const auto& method : *methods) {
            const auto method_key = StringMethodKey(klass.descriptor, method);
            std::uint32_t encryption_applications = 0U;
            std::uint32_t splitting_applications = 0U;
            std::uint32_t reflection_applications = 0U;
            std::uint32_t loading_applications = 0U;
            std::uint32_t indirect_applications = 0U;
            std::vector<const dex::MethodBodySpec::ReferencePatch*> string_patches;
            for (const auto& patch : method.body.references)
                if (std::holds_alternative<std::string>(patch.reference))
                    string_patches.push_back(&patch);
            std::sort(string_patches.begin(), string_patches.end(),
                [](const auto* left, const auto* right) { return left->code_unit < right->code_unit; });
            std::size_t ordinal = 0U;
            for (const auto* item : string_patches) {
                const auto& patch = *item;
                const auto* value = std::get_if<std::string>(&patch.reference);
                const auto stable_site = method_key + ':' + std::to_string(ordinal++);
                if (patch.code_unit == 0U) {
                    throw std::logic_error("const-string reference patch has no opcode");
                }
                const auto site = method_key + ':' +
                                  std::to_string(patch.code_unit - 1U);
                const auto string_offset = patch.code_unit - 1U;
                if (string_offset >= method.body.code_units.size()) continue;
                const auto string_register = static_cast<std::uint16_t>(
                    method.body.code_units[string_offset] >> 8U);
                const auto sensitive = ClassifyStringSite(
                    method, string_offset, string_register);
                const auto encryption_selected = StringPassRequired(
                    encryption, encryption_applications);
                const auto splitting_selected = StringPassSelected(
                    splitting, config.seed, site, 0x53545253U,
                    splitting_applications);
                const auto reflection_selected =
                    (sensitive & kReflectionEncryptionSite) != 0U &&
                    StringPassSelected(reflection, config.seed, site,
                                       0x5245464cU,
                                       reflection_applications);
                const auto loading_selected =
                    (sensitive & kEncryptedLoadingSite) != 0U &&
                    StringPassSelected(loading, config.seed, site,
                                       0x4c4f4144U,
                                       loading_applications);
                const auto indirect_selected =
                    (sensitive & kIndirectReflectionSite) != 0U &&
                    StringPassSelected(indirect, config.seed, site,
                                       0x494e4449U,
                                       indirect_applications);
                if (encryption_selected || splitting_selected || reflection_selected ||
                    loading_selected || indirect_selected) {
                    plan.values.insert(*value);
                    auto& planned = plan.sites[stable_site];
                    planned.value = *value;
                    auto& mask = planned.mask;
                    if (encryption_selected) mask |= kStringEncryptionSite;
                    if (splitting_selected) mask |= kStringSplittingSite;
                    if (splitting_selected) plan.split_values.insert(*value);
                    if (reflection_selected) mask |= kReflectionEncryptionSite;
                    if (loading_selected) mask |= kEncryptedLoadingSite;
                    if (indirect_selected) mask |= kIndirectReflectionSite;
                }
            }
        }
    }
}


std::vector<std::uint8_t> ModelStringProtection::RewriteStringCallsites(
    const dex::DexFile& source, const StringRewritePlan& plan,
    std::string_view helper_descriptor, std::uint64_t seed,
    std::size_t& rewritten_count, ModelLoweringResult& report) {
    std::vector<dex::CodePrefix> prefixes;
    rewritten_count = 0U;
    for (std::size_t class_index = 0U; class_index < source.classes().size();
         ++class_index) {
        const auto owner = source.descriptor(source.classes()[class_index].class_idx);
        if (owner == helper_descriptor) continue;
        const auto& data = source.class_data(class_index);
        const auto collect = [&](const std::vector<dex::DexEncodedMethod>& methods) {
            for (const auto& encoded : methods) {
                if (encoded.code_off == 0U) continue;
                const auto& method = source.methods().at(encoded.method_idx);
                const auto method_key = ParsedStringMethodKey(source, method);
                const auto code = dex::DecodeCodeItem(source, encoded.code_off);
                dex::CodePrefix prefix;
                prefix.code_off = encoded.code_off;
                std::size_t ordinal = 0U;
                for (const auto& instruction : code.instructions) {
                    if (instruction.opcode != 0x1aU && instruction.opcode != 0x1bU) continue;
                    const auto string_index = instruction.opcode == 0x1aU ?
                        static_cast<std::uint32_t>(instruction.code_units.at(1U)) :
                        static_cast<std::uint32_t>(instruction.code_units.at(1U)) |
                            static_cast<std::uint32_t>(instruction.code_units.at(2U)) << 16U;
                    const auto value = source.string(string_index);
                    const auto site = method_key + ':' + std::to_string(ordinal++);
                    const auto planned = plan.sites.find(site);
                    if (planned == plan.sites.end()) continue;
                    if (planned->second.value != value || !plan.values.contains(value))
                        throw std::runtime_error("string-vault site identity changed for " + site);
                    const auto helper_name = RuntimeStringMethodName(value, seed);
                    const auto helper_method = FindStringHelperMethod(
                        source, helper_descriptor, helper_name);
                    if (!helper_method.has_value() || *helper_method > 0xffffU) {
                        throw std::runtime_error("string helper method is missing or exceeds invoke index width");
                    }
                    const auto destination = static_cast<std::uint16_t>(
                        instruction.code_units.front() >> 8U);
                    if (destination > 0xffU) {
                        throw std::runtime_error("const-string destination register exceeds move-result width");
                    }
                    prefix.linear_replacements.emplace(
                        instruction.offset,
                        std::vector<std::uint16_t>{
                            0x0071U, static_cast<std::uint16_t>(*helper_method), 0U,
                            static_cast<std::uint16_t>(0x0cU | (destination << 8U))});
                    ++rewritten_count;
                    if ((planned->second.mask & kStringEncryptionSite) != 0U) {
                        ++report.pass_applications["data.string_encryption"];
                    }
                    if ((planned->second.mask & kStringSplittingSite) != 0U) {
                        ++report.pass_applications["data.string_splitting"];
                    }
                    if ((planned->second.mask & kReflectionEncryptionSite) != 0U) {
                        ++report.pass_applications[
                            "data.reflection_string_encryption"];
                    }
                    if ((planned->second.mask & kEncryptedLoadingSite) != 0U) {
                        ++report.pass_applications["loading.encrypted_paths"];
                    }
                }
                if (!prefix.linear_replacements.empty()) prefixes.push_back(std::move(prefix));
            }
        };
        collect(data.direct_methods);
        collect(data.virtual_methods);
    }
    if (rewritten_count != plan.sites.size()) {
        throw std::runtime_error("string-vault site plan was not fully consumed: planned " +
            std::to_string(plan.sites.size()) + ", rewritten " +
            std::to_string(rewritten_count));
    }
    if (prefixes.empty()) return source.Write();
    return dex::RewriteCodePrefixes(source, prefixes);
}


} // namespace birch::guard::detail
