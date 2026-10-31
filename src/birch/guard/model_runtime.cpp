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

#include "model_runtime.h"
#include "model_support.h"

namespace birch::guard::detail {
namespace {

std::string AllocateOpaqueHelperDescriptor(
    const std::set<std::string, std::less<>>& descriptors,
    std::uint64_t seed, std::size_t shard) {
    for (std::uint32_t attempt = 0U; attempt < 1024U; ++attempt) {
        auto descriptor = RuntimeOpaqueClassDescriptor(seed, shard, attempt);
        if (!descriptors.contains(descriptor)) return descriptor;
    }
    throw std::runtime_error(
        "cannot allocate a collision-free opaque helper descriptor");
}


void AppendLiteral8(std::vector<std::uint16_t>& code, std::uint8_t opcode,
                    std::uint8_t literal) {
    code.push_back(opcode); // v0 <- v0 op literal
    code.push_back(static_cast<std::uint16_t>(literal) << 8U);
}


void AppendLiteral8(std::vector<std::uint16_t>& code, std::uint8_t opcode,
                    std::uint16_t destination, std::uint16_t source,
                    std::uint8_t literal) {
    if (destination > 0xffU || source > 0xffU) {
        throw std::invalid_argument("literal8 register exceeds v255");
    }
    code.push_back(static_cast<std::uint16_t>(
        opcode | (destination << 8U)));
    code.push_back(static_cast<std::uint16_t>(
        source | (static_cast<std::uint16_t>(literal) << 8U)));
}


void AppendMove(std::vector<std::uint16_t>& code, std::uint16_t destination,
                std::uint16_t source) {
    if (destination > 0x0fU || source > 0x0fU) {
        throw std::invalid_argument("move/12x register exceeds v15");
    }
    code.push_back(static_cast<std::uint16_t>(
        0x01U | (destination << 8U) | (source << 12U)));
}


void AppendPredicateReturn(std::vector<std::uint16_t>& code,
                           std::uint16_t zero_register) {
    if (zero_register > 0xffU) {
        throw std::invalid_argument("predicate result register exceeds v255");
    }
    code.insert(code.end(), {
        static_cast<std::uint16_t>(0x39U | (zero_register << 8U)), 4U,
        0x1012U, // const/4 v0, #1
        0x000fU, // return v0
        0x0012U, // false: const/4 v0, #0
        0x000fU,
    });
}


dex::ClassSpec BuildOpaqueHelperShard(
    const std::array<std::string, kRuntimeOpaqueClassShards>& helper_descriptors,
    std::uint64_t descriptor_seed, std::uint64_t method_seed,
    std::size_t shard, const GuardConfig& config) {
    dex::ClassSpec helper;
    helper.descriptor = helper_descriptors.at(shard);
    helper.access_flags = 0x1011U; // public final synthetic
    std::array<std::string, kRuntimeOpaqueStateFields> fields;
    std::array<std::int32_t, kRuntimeOpaqueStateFields> initial_states{};
    for (std::size_t pair = 0U; pair < initial_states.size(); pair += 2U) {
        const auto first = static_cast<std::int32_t>(utils::StableHash64(
            helper.descriptor + ":state:" + std::to_string(pair),
            descriptor_seed));
        initial_states[pair] = first;
        initial_states[pair + 1U] = ~first;
    }
    for (std::size_t slot = 0U; slot < fields.size(); ++slot) {
        fields[slot] = RuntimeOpaqueFieldName(descriptor_seed, shard, slot);
        dex::FieldSpec state;
        state.name = fields[slot];
        state.type = "I";
        state.access_flags = 0x1049U; // public static volatile synthetic
        state.static_value = dex::EncodedValueSpec{initial_states[slot]};
        helper.static_fields.push_back(std::move(state));
    }
    const auto cross_method_name = RuntimeOpaqueMethodName(
        method_seed, kRuntimeOpaquePasses.size() + shard);
    if (shard == 0U &&
        config.passes.at("predicate.cross_process").enabled) {
        dex::MethodSpec supplier;
        supplier.name = cross_method_name;
        supplier.return_type = "I";
        supplier.access_flags = 0x100aU; // private static synthetic
        supplier.body.registers_size = 2U;
        supplier.body.code_units = {0x0060U, 0U}; // sget v0
        supplier.body.references.push_back({
            dex::FieldReference{helper.descriptor, fields[0U], "I"},
            1U, false});
        const auto supplier_key = static_cast<std::uint8_t>(
            utils::StableHash64(helper.descriptor + ":supplier",
                                method_seed) | 1U);
        AppendLiteral8(supplier.body.code_units, 0xdfU, supplier_key);
        const auto supplier_write = static_cast<std::uint32_t>(
            supplier.body.code_units.size() + 1U);
        supplier.body.code_units.insert(supplier.body.code_units.end(),
                                        {0x0067U, 0U});
        supplier.body.references.push_back({
            dex::FieldReference{helper.descriptor, fields[0U], "I"},
            supplier_write, false});
        supplier.body.code_units.push_back(0x000fU);
        helper.direct_methods.push_back(std::move(supplier));
    }
    for (std::size_t strategy = 0U;
         strategy < kRuntimeOpaquePasses.size(); ++strategy) {
        if (strategy % kRuntimeOpaqueClassShards != shard) continue;
        const auto& pass = config.passes.at(
            std::string(kRuntimeOpaquePasses[strategy]));
        if (!pass.enabled) continue;
        dex::MethodSpec method;
        method.name = RuntimeOpaqueMethodName(method_seed, strategy);
        method.return_type = "I";
        method.access_flags = 0x1029U; // public static synchronized synthetic
        method.body.registers_size = 6U;
        // Include a runtime class identity in every predicate.  It is folded
        // into the volatile state relation below, so a static analyzer cannot
        // reduce the helper to its build-time field initializers.
        method.body.outs_size = 1U;
        method.body.code_units.insert(method.body.code_units.end(), {
            0x021cU, 0U, // const-class v2, helper
        });
        method.body.references.push_back({
            dex::TypeReference{helper.descriptor}, 1U, false});
        AppendInvoke35c(
            method.body.code_units, 0x71U, {2U}, method.body,
            dex::MethodReference{"Ljava/lang/System;", "identityHashCode",
                                 "I", {"Ljava/lang/Object;"}});
        method.body.code_units.push_back(0x020aU); // move-result v2
        method.body.code_units.push_back(0x2501U); // move v5, v2
        const auto first_slot = (strategy & 1U) * 2U;
        const auto second_slot = first_slot + 1U;
        const auto first_owner = strategy == 5U ?
            helper_descriptors.at((shard + 1U) % kRuntimeOpaqueClassShards) :
            helper.descriptor;
        const auto first_field = strategy == 5U ?
            RuntimeOpaqueFieldName(
                descriptor_seed,
                (shard + 1U) % kRuntimeOpaqueClassShards, first_slot) :
            fields[first_slot];
        const auto sget_first = static_cast<std::uint32_t>(
            method.body.code_units.size() + 1U);
        method.body.code_units.insert(method.body.code_units.end(),
                                      {0x0060U, 0U}); // sget v0
        method.body.references.push_back({
            dex::FieldReference{first_owner, first_field, "I"},
            sget_first, false});
        const auto sget_second = static_cast<std::uint32_t>(
            method.body.code_units.size() + 1U);
        method.body.code_units.insert(method.body.code_units.end(),
                                      {0x0160U, 0U}); // sget v1
        method.body.references.push_back({
            dex::FieldReference{helper.descriptor, fields[second_slot], "I"},
            sget_second, false});
        method.body.code_units.push_back(0x10b7U); // xor-int/2addr v0, v1
        auto mixed = utils::StableHash64(
            std::string(kRuntimeOpaquePasses[strategy]), method_seed);
        method.body.code_units.push_back(0x0114U); // const v1
        method.body.code_units.push_back(static_cast<std::uint16_t>(mixed));
        method.body.code_units.push_back(
            static_cast<std::uint16_t>(mixed >> 16U));
        method.body.code_units.push_back(0x10b7U); // xor-int/2addr v0, v1
        switch (strategy) {
            case 0U: // number-theory modular residue chain
                AppendLiteral8(method.body.code_units, 0xdaU, 31U);
                AppendLiteral8(method.body.code_units, 0xdcU, 127U);
                AppendLiteral8(method.body.code_units, 0xd8U, 17U);
                break;
            case 1U: // polynomial Horner chain
                AppendLiteral8(method.body.code_units, 0xdaU, 13U);
                AppendLiteral8(method.body.code_units, 0xd8U, 5U);
                AppendLiteral8(method.body.code_units, 0xdaU, 17U);
                AppendLiteral8(method.body.code_units, 0xd8U, 7U);
                break;
            case 2U: // two-register matrix-like mixing
                method.body.code_units.push_back(0x10b2U); // mul-int/2addr v0,v1
                method.body.code_units.push_back(0x10b0U); // add-int/2addr v0,v1
                method.body.code_units.push_back(0x10b7U); // xor-int/2addr v0,v1
                break;
            case 3U: // reversible bit permutation rounds
                AppendLiteral8(method.body.code_units, 0xdfU, 0x5bU);
                AppendLiteral8(method.body.code_units, 0xe0U, 5U);
                AppendLiteral8(method.body.code_units, 0xe2U, 3U);
                AppendLiteral8(method.body.code_units, 0xdfU, 0xa7U);
                break;
            case 4U: // cross-procedure state diffusion
                method.body.code_units.insert(method.body.code_units.end(),
                                              {0x0071U, 0U, 0U});
                method.body.references.push_back({
                    dex::MethodReference{helper.descriptor, cross_method_name,
                                         "I", {}},
                    static_cast<std::uint32_t>(
                        method.body.code_units.size() - 2U), false});
                method.body.code_units.push_back(0x020aU); // move-result v2
                method.body.code_units.push_back(0x20b7U); // xor-int/2addr v0,v2
                AppendLiteral8(method.body.code_units, 0xdaU, 33U);
                AppendLiteral8(method.body.code_units, 0xdfU, 0x6dU);
                break;
            case 5U: // cross-class volatile state dependency
                AppendLiteral8(method.body.code_units, 0xd8U, 29U);
                method.body.code_units.push_back(0x10b7U);
                break;
            case 6U: // execution-history rolling hash
                AppendLiteral8(method.body.code_units, 0xdaU, 37U);
                AppendLiteral8(method.body.code_units, 0xd8U, 11U);
                AppendLiteral8(method.body.code_units, 0xdfU, 0xc3U);
                break;
            case 7U: // defined Dalvik int overflow behavior
                AppendLiteral8(method.body.code_units, 0xd8U, 0x7fU);
                AppendLiteral8(method.body.code_units, 0xdaU, 0x7dU);
                AppendLiteral8(method.body.code_units, 0xd8U, 0x7fU);
                break;
            case 8U: // NaN comparison and deterministic floating-point behavior
                method.body.code_units.insert(method.body.code_units.end(), {
                    0x0314U, 0x0000U, 0x7fc0U, // const v3, quiet NaN
                    0x0414U, 0x0000U, 0x3f80U, // const v4, 1.0f
                    0x022dU, 0x0403U,          // cmpl-float v2,v3,v4 => -1
                });
                break;
            case 9U: {
                method.body.code_units.insert(method.body.code_units.end(), {
                    0x0114U, 0x0046U, 0x0000U, // const v1, first char
                    0x01daU,                   // mul-int/lit8 v1,v1,#31
                    0x1f01U,
                    0x01d8U,                   // add-int/lit8 v1,v1,#66
                    0x4201U,
                    0x0214U, 0x0045U, 0x0000U, // const v2, first char
                    0x02daU,                   // mul-int/lit8 v2,v2,#31
                    0x1f02U,
                    0x02d8U,                   // add-int/lit8 v2,v2,#97
                    0x6102U,
                });
                method.body.code_units.push_back(0x0097U); // xor-int v0,v1,v2
                method.body.code_units.push_back(0x0201U);
                AppendMove(method.body.code_units, 2U, 0U);
                break;
            }
            case 10U: // ARX rounds used by stream/block cipher constructions
                for (std::uint32_t round = 0U; round < 8U; ++round) {
                    AppendLiteral8(method.body.code_units, 0xd8U,
                                   static_cast<std::uint8_t>(0x9dU + round * 17U));
                    AppendLiteral8(method.body.code_units, 0xe0U,
                                   static_cast<std::uint8_t>(3U + round % 5U));
                    AppendLiteral8(method.body.code_units, 0xdfU,
                                   static_cast<std::uint8_t>(0x63U + round * 29U));
                    AppendLiteral8(method.body.code_units, 0xe2U,
                                   static_cast<std::uint8_t>(5U + round % 7U));
                }
                break;
            case 11U: // fixed graph reachability over a packed adjacency bitset
                for (std::uint32_t round = 0U; round < 6U; ++round) {
                    AppendLiteral8(method.body.code_units, 0xe0U, 1U);
                    AppendLiteral8(method.body.code_units, 0xdeU,
                                   static_cast<std::uint8_t>(1U << (round % 7U)));
                    AppendLiteral8(method.body.code_units, 0xddU, 0x7fU);
                }
                break;
            case 12U: { // app class-loader identity feeds the state
                method.body.code_units.push_back(0x001cU); // const-class v0
                method.body.references.push_back(
                    {dex::TypeReference{helper.descriptor},
                     static_cast<std::uint32_t>(method.body.code_units.size()), false});
                method.body.code_units.push_back(0U);
                const dex::MethodReference get_loader{
                    "Ljava/lang/Class;", "getClassLoader",
                    "Ljava/lang/ClassLoader;", {}};
                AppendInvoke35c(method.body.code_units, 0x6eU, {0U},
                                method.body, get_loader);
                method.body.code_units.push_back(0x000cU); // move-result-object v0
                const dex::MethodReference identity_hash{
                    "Ljava/lang/System;", "identityHashCode", "I",
                    {"Ljava/lang/Object;"}};
                AppendInvoke35c(method.body.code_units, 0x71U, {0U},
                                method.body, identity_hash);
                method.body.code_units.push_back(0x000aU); // move-result v0
                break;
            }
            case 13U: { // two independently loaded references to the same Class object
                for (std::uint16_t reg = 0U; reg < 2U; ++reg) {
                    method.body.code_units.push_back(static_cast<std::uint16_t>(
                        0x1cU | (reg << 8U)));
                    method.body.references.push_back(
                        {dex::TypeReference{helper.descriptor},
                         static_cast<std::uint32_t>(method.body.code_units.size()),
                         false});
                    method.body.code_units.push_back(0U);
                }
                method.body.code_units.insert(method.body.code_units.end(), {
                    0x1033U, 4U, // if-ne v0,v1,false
                    0x1012U,     // const/4 v0,#1
                    0x0228U,     // goto common
                    0x0012U,     // false: const/4 v0,#0
                });
                AppendMove(method.body.code_units, 2U, 0U);
                break;
            }
            default:
                throw std::logic_error("opaque helper strategy index is invalid");
        }
        const auto diffusion_rounds = 8U + static_cast<std::uint32_t>(
            std::ceil(pass.intensity * 24.0));
        for (std::uint32_t round = 0U; round < diffusion_rounds; ++round) {
            const auto round_seed = utils::StableHash64(
                std::string(kRuntimeOpaquePasses[strategy]) + ':' +
                    std::to_string(round),
                method_seed ^ mixed);
            AppendLiteral8(method.body.code_units, 0xd8U,
                           static_cast<std::uint8_t>(round_seed | 1U));
            AppendLiteral8(method.body.code_units, 0xe0U,
                           static_cast<std::uint8_t>(
                               1U + ((round_seed >> 9U) % 7U)));
            AppendLiteral8(method.body.code_units, 0xdfU,
                           static_cast<std::uint8_t>(
                               (round_seed >> 23U) | 1U));
            AppendLiteral8(method.body.code_units, 0xe2U,
                           static_cast<std::uint8_t>(
                               1U + ((round_seed >> 41U) % 7U)));
        }
        method.body.code_units.push_back(0x50b7U); // fold preserved runtime identity
        const auto write_first = first_slot;
        const auto write_second = second_slot;
        const auto sput_first = static_cast<std::uint32_t>(
            method.body.code_units.size() + 1U);
        method.body.code_units.insert(method.body.code_units.end(),
                                      {0x0067U, 0U}); // sput v0
        method.body.references.push_back({
            dex::FieldReference{helper.descriptor, fields[write_first], "I"},
            sput_first, false});
        // Publish a strategy-specific state relation. The method is
        // synchronized so another invocation cannot observe only one half of
        // the update. Alternating xor/add relations avoid a common tail
        // fingerprint across all predicate families.
        auto relation_key = static_cast<std::uint8_t>(
            (mixed >> 17U) | 1U);
        if (relation_key == 0x80U) relation_key = 0x7fU;
        AppendLiteral8(method.body.code_units,
                       (strategy & 1U) == 0U ? 0xdfU : 0xd8U,
                       1U, 0U, relation_key);
        const auto sput_second = static_cast<std::uint32_t>(
            method.body.code_units.size() + 1U);
        method.body.code_units.insert(method.body.code_units.end(),
                                      {0x0167U, 0U}); // sput v1
        method.body.references.push_back({
            dex::FieldReference{helper.descriptor, fields[write_second], "I"},
            sput_second, false});
        // Re-read the volatile pair. Each strategy below proves a different
        // invariant over state that crossed volatile memory.
        const auto reload_first = static_cast<std::uint32_t>(
            method.body.code_units.size() + 1U);
        method.body.code_units.insert(method.body.code_units.end(), {
            0x0060U, 0U, // sget v0, first
        });
        method.body.references.push_back({
            dex::FieldReference{helper.descriptor, fields[write_first], "I"},
            reload_first, false});
        const auto reload_second = static_cast<std::uint32_t>(
            method.body.code_units.size() + 1U);
        method.body.code_units.insert(method.body.code_units.end(), {
            0x0160U, 0U, // sget v1, second
        });
        method.body.references.push_back({
            dex::FieldReference{helper.descriptor, fields[write_second], "I"},
            reload_second, false});
        std::uint16_t result_register = 2U;
        switch (strategy) {
            case 0U: // Fermat: a^30 mod 31 == 1 for a in [1,30]
                AppendLiteral8(method.body.code_units, 0xddU, 2U, 0U, 0x1fU);
                AppendLiteral8(method.body.code_units, 0xdcU, 2U, 2U, 30U);
                AppendLiteral8(method.body.code_units, 0xd8U, 2U, 2U, 1U);
                method.body.code_units.push_back(0x1312U); // const/4 v3,#1
                for (std::uint32_t exponent = 0U; exponent < 30U; ++exponent) {
                    method.body.code_units.push_back(0x23b2U);
                    AppendLiteral8(method.body.code_units, 0xdcU, 3U, 3U,
                                   31U);
                }
                AppendLiteral8(method.body.code_units, 0xd8U, 3U, 3U, 0xffU);
                result_register = 3U;
                break;
            case 1U: // (x+1)^4 expanded in the integer ring modulo 2^32
                AppendMove(method.body.code_units, 2U, 0U);
                AppendLiteral8(method.body.code_units, 0xd8U, 2U, 2U, 1U);
                method.body.code_units.push_back(0x22b2U);
                method.body.code_units.push_back(0x22b2U);
                AppendMove(method.body.code_units, 3U, 0U);
                method.body.code_units.push_back(0x03b2U);
                AppendMove(method.body.code_units, 4U, 3U);
                method.body.code_units.push_back(0x04b2U);
                AppendMove(method.body.code_units, 5U, 4U);
                method.body.code_units.push_back(0x05b2U);
                AppendLiteral8(method.body.code_units, 0xdaU, 4U, 4U, 4U);
                method.body.code_units.push_back(0x45b0U);
                AppendMove(method.body.code_units, 4U, 3U);
                AppendLiteral8(method.body.code_units, 0xdaU, 4U, 4U, 6U);
                method.body.code_units.push_back(0x45b0U);
                AppendMove(method.body.code_units, 4U, 0U);
                AppendLiteral8(method.body.code_units, 0xdaU, 4U, 4U, 4U);
                method.body.code_units.push_back(0x45b0U);
                AppendLiteral8(method.body.code_units, 0xd8U, 5U, 5U, 1U);
                method.body.code_units.push_back(0x52b7U);
                break;
            case 2U: // determinant of [[1,2x],[0,1]] is one
                AppendMove(method.body.code_units, 2U, 0U);
                method.body.code_units.push_back(0x02b0U);
                AppendLiteral8(method.body.code_units, 0xdaU, 3U, 2U, 0U);
                method.body.code_units.push_back(0x1412U);
                method.body.code_units.push_back(0x34b1U);
                AppendLiteral8(method.body.code_units, 0xd8U, 4U, 4U, 0xffU);
                result_register = 4U;
                break;
            case 3U: { // multi-round reversible bit/arithmetic permutation
                AppendMove(method.body.code_units, 2U, 0U);
                std::array<std::uint8_t, 16U> xor_keys{};
                std::array<std::uint8_t, 16U> add_keys{};
                for (std::size_t round = 0U; round < xor_keys.size(); ++round) {
                    const auto round_seed = utils::StableHash64(
                        "bitwise-validation:" + std::to_string(round), mixed);
                    xor_keys[round] = static_cast<std::uint8_t>(round_seed | 1U);
                    add_keys[round] = static_cast<std::uint8_t>(
                        1U + ((round_seed >> 19U) % 0x7eU));
                    AppendLiteral8(method.body.code_units, 0xdfU, 2U, 2U,
                                   xor_keys[round]);
                    AppendLiteral8(method.body.code_units, 0xd8U, 2U, 2U,
                                   add_keys[round]);
                }
                for (std::size_t round = add_keys.size(); round > 0U; --round) {
                    AppendLiteral8(method.body.code_units, 0xd8U, 2U, 2U,
                        static_cast<std::uint8_t>(
                            -static_cast<std::int8_t>(add_keys[round - 1U])));
                    AppendLiteral8(method.body.code_units, 0xdfU, 2U, 2U,
                                   xor_keys[round - 1U]);
                }
                method.body.code_units.push_back(0x02b7U);
                break;
            }
            case 4U: // value returned by the auxiliary method crosses a call boundary
            case 6U: // rolling-history state relation
                AppendMove(method.body.code_units, 2U, 1U);
                AppendLiteral8(method.body.code_units, 0xdfU, 2U, 2U,
                               relation_key);
                method.body.code_units.push_back(0x02b7U);
                break;
            case 10U: { // reversible ARX known-pair relation
                AppendMove(method.body.code_units, 2U, 0U);
                AppendMove(method.body.code_units, 3U, 1U);
                std::array<std::uint8_t, 16U> left_keys{};
                std::array<std::uint8_t, 16U> right_keys{};
                for (std::size_t round = 0U; round < left_keys.size(); ++round) {
                    const auto round_seed = utils::StableHash64(
                        "crypto-validation:" + std::to_string(round), mixed);
                    left_keys[round] = static_cast<std::uint8_t>(
                        1U + (round_seed % 0x7eU));
                    right_keys[round] = static_cast<std::uint8_t>(
                        (round_seed >> 23U) | 1U);
                    AppendLiteral8(method.body.code_units, 0xd8U, 2U, 2U,
                                   left_keys[round]);
                    AppendLiteral8(method.body.code_units, 0xdfU, 3U, 3U,
                                   right_keys[round]);
                    method.body.code_units.push_back(0x32b7U);
                }
                for (std::size_t round = left_keys.size(); round > 0U; --round) {
                    method.body.code_units.push_back(0x32b7U);
                    AppendLiteral8(method.body.code_units, 0xdfU, 3U, 3U,
                                   right_keys[round - 1U]);
                    AppendLiteral8(method.body.code_units, 0xd8U, 2U, 2U,
                        static_cast<std::uint8_t>(
                            -static_cast<std::int8_t>(left_keys[round - 1U])));
                }
                method.body.code_units.push_back(0x02b7U);
                method.body.code_units.push_back(0x13b7U);
                method.body.code_units.push_back(0x32b6U);
                break;
            }
            case 5U: // value originated from another helper class
            case 12U: // class-loader identity is otherwise unconstrained
                AppendMove(method.body.code_units, 2U, 0U);
                AppendLiteral8(method.body.code_units, 0xd8U, 3U, 0U, 0xffU);
                method.body.code_units.push_back(0x32b2U);
                AppendLiteral8(method.body.code_units, 0xddU, 2U, 2U, 1U);
                break;
            case 7U: // adding Integer.MIN_VALUE twice wraps to the input
                AppendMove(method.body.code_units, 2U, 0U);
                method.body.code_units.insert(method.body.code_units.end(),
                                              {0x0314U, 0U, 0x8000U});
                method.body.code_units.push_back(0x32b0U);
                method.body.code_units.push_back(0x32b0U);
                method.body.code_units.push_back(0x02b7U);
                break;
            case 8U: // cmpl-float(NaN, finite) == -1
                AppendLiteral8(method.body.code_units, 0xd8U, 2U, 2U, 1U);
                break;
            case 9U: // arithmetic Java hashes for FB and Ea collide
                break;
            case 11U: // fixed graph expansion reaches vertex six
                method.body.code_units.push_back(0x1212U); // const/4 v2,#1
                for (std::uint32_t edge = 0U; edge < 6U; ++edge) {
                    AppendLiteral8(method.body.code_units, 0xe0U, 2U, 2U, 1U);
                    AppendLiteral8(method.body.code_units, 0xdeU, 2U, 2U, 1U);
                }
                AppendLiteral8(method.body.code_units, 0xddU, 2U, 2U, 0x40U);
                AppendLiteral8(method.body.code_units, 0xdfU, 2U, 2U, 0x40U);
                break;
            case 13U: // independently loaded Class references are identical
                AppendLiteral8(method.body.code_units, 0xd8U, 2U, 2U, 0xffU);
                break;
            default:
                throw std::logic_error("opaque validation strategy is invalid");
        }
        AppendPredicateReturn(method.body.code_units, result_register);
        helper.direct_methods.push_back(std::move(method));
    }
    return helper;
}


std::string AllocateExceptionHelperDescriptor(
    const std::set<std::string, std::less<>>& descriptors,
    std::uint64_t seed) {
    for (std::uint32_t attempt = 0U; attempt < 1024U; ++attempt) {
        auto descriptor = RuntimeExceptionClassDescriptor(seed, attempt);
        if (!descriptors.contains(descriptor)) return descriptor;
    }
    throw std::runtime_error(
        "cannot allocate a collision-free exception helper descriptor");
}


} // namespace

bool ModelRuntimeBuilder::HasRuntimeOpaquePasses(const GuardConfig& config) {
    return std::any_of(kRuntimeOpaquePasses.begin(),
                       kRuntimeOpaquePasses.end(), [&](const auto id) {
        const auto found = config.passes.find(std::string(id));
        if (found == config.passes.end()) {
            throw std::invalid_argument("missing pass configuration: " +
                                        std::string(id));
        }
        return found->second.enabled;
    });
}


bool ModelRuntimeBuilder::HasRuntimeExceptionPasses(const GuardConfig& config) {
    return std::any_of(kRuntimeExceptionPasses.begin(),
                       kRuntimeExceptionPasses.end(), [&](const auto id) {
        const auto found = config.passes.find(std::string(id));
        if (found == config.passes.end()) {
            throw std::invalid_argument("missing pass configuration: " +
                                        std::string(id));
        }
        return found->second.enabled;
    });
}


bool ModelRuntimeBuilder::HasRuntimeConstantPasses(const GuardConfig& config) {
    return config.passes.at("data.constant_splitting").enabled ||
           config.passes.at("data.boolean_arithmetic").enabled ||
           config.passes.at("anti_analysis.constant_barriers").enabled ||
           config.passes.at("anti_analysis.instruction_patterns").enabled;
}


dex::ClassSpec ModelRuntimeBuilder::BuildConstantBarrierHelper(
    const std::set<std::string, std::less<>>& descriptors,
    std::uint64_t descriptor_seed, std::uint64_t method_seed) {
    dex::ClassSpec helper;
    helper.descriptor = SyntheticClassDescriptor(
        "constant-runtime", "data", descriptor_seed, 0U, descriptors);
    helper.access_flags = 0x1011U; // public final synthetic

    const auto initial = static_cast<std::int32_t>(utils::StableHash64(
        helper.descriptor + ":constant-state", descriptor_seed));
    const std::array<std::int32_t, kRuntimeConstantStateFields> values{
        initial, ~initial};
    std::array<std::string, kRuntimeConstantStateFields> fields;
    for (std::size_t slot = 0U; slot < fields.size(); ++slot) {
        fields[slot] = RuntimeConstantFieldName(method_seed, slot);
        dex::FieldSpec field;
        field.name = fields[slot];
        field.type = "I";
        field.access_flags = 0x104aU; // private static volatile synthetic
        field.static_value = dex::EncodedValueSpec{values[slot]};
        helper.static_fields.push_back(std::move(field));
    }
    const auto null_field = RuntimeNullConstantFieldName(method_seed);
    dex::FieldSpec object_field;
    object_field.name = null_field;
    object_field.type = "Ljava/lang/Object;";
    object_field.access_flags = 0x104aU; // private static volatile synthetic
    helper.static_fields.push_back(std::move(object_field));

    dex::MethodSpec method;
    method.name = RuntimeConstantMethodName(method_seed);
    method.return_type = "I";
    method.parameter_types = {"I"};
    method.access_flags = 0x1029U; // public static synchronized synthetic
    method.body.registers_size = 5U;
    method.body.outs_size = 1U;
    method.body.ins_size = 1U;
    auto& code = method.body.code_units;
    // The reversible barrier also depends on a runtime class identity.  The
    // volatile state pair still recovers the caller's value exactly, while
    // constant propagation cannot precompute the complete key.
    code.insert(code.end(), {0x031cU, 0U}); // const-class v3, helper
    method.body.references.push_back({
        dex::TypeReference{helper.descriptor}, 1U, false});
    AppendInvoke35c(
        code, 0x71U, {3U}, method.body,
        dex::MethodReference{"Ljava/lang/System;", "identityHashCode",
                             "I", {"Ljava/lang/Object;"}});
    code.push_back(0x030aU); // move-result v3
    code.insert(code.end(), {0x0060U, 0U}); // sget v0, first
    method.body.references.push_back({
        dex::FieldReference{helper.descriptor, fields[0U], "I"}, 7U, false});
    code.insert(code.end(), {0x0160U, 0U}); // sget v1, second
    method.body.references.push_back({
        dex::FieldReference{helper.descriptor, fields[1U], "I"}, 9U, false});
    code.insert(code.end(), {
        0x4201U, // move v2, p0(v4)
        0x32b7U, // xor-int/2addr v2, v3 (runtime class identity)
        0x02b7U, // xor-int/2addr v2, v0
        0x12b7U, // xor-int/2addr v2, v1
    });
    std::array<std::uint8_t, 16U> additions{};
    std::array<std::uint8_t, 16U> masks{};
    auto state = utils::StableHash64(helper.descriptor, method_seed);
    for (std::size_t round = 0U; round < additions.size(); ++round) {
        state ^= state << 13U;
        state ^= state >> 7U;
        state ^= state << 17U;
        additions[round] = static_cast<std::uint8_t>(state | 1U);
        masks[round] = static_cast<std::uint8_t>((state >> 29U) | 1U);
        code.insert(code.end(), {
            0x02d8U, static_cast<std::uint16_t>(
                2U | (static_cast<std::uint16_t>(additions[round]) << 8U)),
            0x02dfU, static_cast<std::uint16_t>(
                2U | (static_cast<std::uint16_t>(masks[round]) << 8U)),
        });
    }
    for (std::size_t reverse = additions.size(); reverse != 0U; --reverse) {
        const auto round = reverse - 1U;
        const auto inverse_add = static_cast<std::uint8_t>(
            0U - additions[round]);
        code.insert(code.end(), {
            0x02dfU, static_cast<std::uint16_t>(
                2U | (static_cast<std::uint16_t>(masks[round]) << 8U)),
            0x02d8U, static_cast<std::uint16_t>(
                2U | (static_cast<std::uint16_t>(inverse_add) << 8U)),
        });
    }
    code.insert(code.end(), {
        0x03b7U, // xor-int/2addr v3, v0
        0x13b7U, // xor-int/2addr v3, v1 (same runtime-derived mask)
        0x32b7U, // xor-int/2addr v2, v3: recover p0 through field invariant
        0x00d8U, static_cast<std::uint16_t>(0x5d00U), // v0 += 0x5d
        0x017cU, // not-int v1, v0
        0x0067U, 0U, // sput v0, first
    });
    method.body.references.push_back({
        dex::FieldReference{helper.descriptor, fields[0U], "I"},
        static_cast<std::uint32_t>(code.size() - 1U), false});
    code.insert(code.end(), {0x0167U, 0U}); // sput v1, second
    method.body.references.push_back({
        dex::FieldReference{helper.descriptor, fields[1U], "I"},
        static_cast<std::uint32_t>(code.size() - 1U), false});
    code.push_back(0x020fU); // return v2
    helper.direct_methods.push_back(std::move(method));

    dex::MethodSpec float_method;
    float_method.name = RuntimeFloatConstantMethodName(method_seed);
    float_method.return_type = "F";
    float_method.parameter_types = {"I"};
    float_method.access_flags = 0x1009U; // public static synthetic
    float_method.body.registers_size = 2U;
    float_method.body.outs_size = 1U;
    float_method.body.ins_size = 1U;
    auto& float_code = float_method.body.code_units;
    AppendInvoke35c(
        float_code, 0x71U, {1U}, float_method.body,
        dex::MethodReference{helper.descriptor,
                             RuntimeConstantMethodName(method_seed), "I", {"I"}});
    float_code.push_back(0x000aU); // move-result v0 (int bits)
    AppendInvoke35c(
        float_code, 0x71U, {0U}, float_method.body,
        dex::MethodReference{"Ljava/lang/Float;", "intBitsToFloat", "F", {"I"}});
    float_code.push_back(0x000aU); // move-result v0 (float)
    float_code.push_back(0x000fU); // return v0
    helper.direct_methods.push_back(std::move(float_method));

    dex::MethodSpec null_method;
    null_method.name = RuntimeNullConstantMethodName(method_seed);
    null_method.return_type = "Ljava/lang/Object;";
    null_method.parameter_types = {"I"};
    null_method.access_flags = 0x1009U; // public static synthetic
    null_method.body.registers_size = 2U;
    null_method.body.outs_size = 1U;
    null_method.body.ins_size = 1U;
    auto& null_code = null_method.body.code_units;
    AppendInvoke35c(
        null_code, 0x71U, {1U}, null_method.body,
        dex::MethodReference{helper.descriptor,
                             RuntimeConstantMethodName(method_seed), "I", {"I"}});
    null_code.push_back(0x000aU); // consume the runtime barrier result
    null_code.insert(null_code.end(), {0x0062U, 0U}); // sget-object v0
    null_method.body.references.push_back({
        dex::FieldReference{helper.descriptor, null_field,
                            "Ljava/lang/Object;"},
        static_cast<std::uint32_t>(null_code.size() - 1U), false});
    null_code.push_back(0x0011U); // return-object v0
    helper.direct_methods.push_back(std::move(null_method));
    return helper;
}


std::vector<dex::ClassSpec> ModelRuntimeBuilder::BuildOpaqueHelpers(
    const std::set<std::string, std::less<>>& descriptors,
    std::uint64_t descriptor_seed, std::uint64_t method_seed,
    const GuardConfig& config) {
    std::vector<dex::ClassSpec> helpers;
    helpers.reserve(kRuntimeOpaqueClassShards);
    auto used = descriptors;
    std::array<std::string, kRuntimeOpaqueClassShards> helper_descriptors;
    for (std::size_t shard = 0U; shard < kRuntimeOpaqueClassShards; ++shard) {
        helper_descriptors[shard] = AllocateOpaqueHelperDescriptor(
            used, descriptor_seed, shard);
        used.insert(helper_descriptors[shard]);
    }
    for (std::size_t shard = 0U; shard < kRuntimeOpaqueClassShards; ++shard) {
        auto helper = BuildOpaqueHelperShard(
            helper_descriptors, descriptor_seed, method_seed, shard, config);
        if (helper.direct_methods.empty() &&
            !config.passes.at("predicate.cross_class_state").enabled) {
            continue;
        }
        helpers.push_back(std::move(helper));
    }
    return helpers;
}


dex::ClassSpec ModelRuntimeBuilder::BuildExceptionFlowHelper(
    const std::set<std::string, std::less<>>& descriptors,
    std::uint64_t descriptor_seed, std::uint64_t method_seed,
    const GuardConfig& config) {
    dex::ClassSpec helper;
    helper.descriptor = AllocateExceptionHelperDescriptor(descriptors,
                                                          descriptor_seed);
    helper.access_flags = 0x1011U; // public final synthetic

    std::array<std::string, kRuntimeExceptionStateFields> fields;
    const auto initial = static_cast<std::int32_t>(utils::StableHash64(
        helper.descriptor + ":exception-state", descriptor_seed));
    const std::array<std::int32_t, kRuntimeExceptionStateFields> values{
        initial, ~initial};
    for (std::size_t slot = 0U; slot < fields.size(); ++slot) {
        fields[slot] = RuntimeExceptionFieldName(method_seed, slot);
        dex::FieldSpec field;
        field.name = fields[slot];
        field.type = "I";
        field.access_flags = 0x1049U; // public static volatile synthetic
        field.static_value = dex::EncodedValueSpec{values[slot]};
        helper.static_fields.push_back(std::move(field));
    }

    double intensity = 0.0;
    for (const auto id : kRuntimeExceptionPasses) {
        const auto& pass = config.passes.at(std::string(id));
        if (pass.enabled) intensity = std::max(intensity, pass.intensity);
    }

    dex::MethodSpec method;
    method.name = RuntimeExceptionMethodName(method_seed);
    method.return_type = "I";
    method.access_flags = 0x1029U; // public static synchronized synthetic
    method.body.registers_size = 4U;
    method.body.outs_size = 1U;
    auto& code = method.body.code_units;
    const auto add_field_reference = [&](std::size_t slot,
                                         std::uint32_t code_unit) {
        method.body.references.push_back({
            dex::FieldReference{helper.descriptor, fields[slot], "I"},
            code_unit, false});
    };

    code.insert(code.end(), {
        0x031cU, 0U, // const-class v3, helper
    });
    method.body.references.push_back({
        dex::TypeReference{helper.descriptor}, 1U, false});
    AppendInvoke35c(
        code, 0x71U, {3U}, method.body,
        dex::MethodReference{"Ljava/lang/System;", "identityHashCode", "I",
                             {"Ljava/lang/Object;"}});
    code.push_back(0x030aU); // move-result v3
    auto reference_at = static_cast<std::uint32_t>(code.size() + 1U);
    code.insert(code.end(), {0x0060U, 0U}); // sget v0, first
    add_field_reference(0U, reference_at);
    reference_at = static_cast<std::uint32_t>(code.size() + 1U);
    code.insert(code.end(), {0x0160U, 0U}); // sget v1, second
    add_field_reference(1U, reference_at);
    code.insert(code.end(), {
        0x10b7U, // xor-int/2addr v0, v1
        0x30b7U, // xor-int/2addr v0, runtime class identity
    });
    const auto mixed = utils::StableHash64("exception-flow-helper", method_seed);
    code.insert(code.end(), {
        0x0214U, static_cast<std::uint16_t>(mixed),
        static_cast<std::uint16_t>(mixed >> 16U), // const v2, mixed
        0x20b7U,                                 // xor-int/2addr v0, v2
    });
    const auto rounds = 12U + static_cast<std::uint32_t>(
        std::ceil(intensity * 36.0));
    for (std::uint32_t round = 0U; round < rounds; ++round) {
        const auto round_seed = utils::StableHash64(
            "exception-flow:" + std::to_string(round), mixed ^ method_seed);
        AppendLiteral8(code, 0xd8U,
                       static_cast<std::uint8_t>(round_seed | 1U));
        AppendLiteral8(code, 0xe0U, static_cast<std::uint8_t>(
            1U + ((round_seed >> 11U) % 7U)));
        AppendLiteral8(code, 0xdfU, static_cast<std::uint8_t>(
            (round_seed >> 29U) | 1U));
        AppendLiteral8(code, 0xe2U, static_cast<std::uint8_t>(
            1U + ((round_seed >> 47U) % 7U)));
    }

    reference_at = static_cast<std::uint32_t>(code.size() + 1U);
    code.insert(code.end(), {0x0067U, 0U}); // sput v0, first
    add_field_reference(0U, reference_at);
    code.insert(code.end(), {0x01dfU, 0xff00U}); // v1 = v0 ^ -1
    reference_at = static_cast<std::uint32_t>(code.size() + 1U);
    code.insert(code.end(), {0x0167U, 0U}); // sput v1, second
    add_field_reference(1U, reference_at);

    reference_at = static_cast<std::uint32_t>(code.size() + 1U);
    code.insert(code.end(), {0x0060U, 0U}); // re-read first
    add_field_reference(0U, reference_at);
    reference_at = static_cast<std::uint32_t>(code.size() + 1U);
    code.insert(code.end(), {0x0160U, 0U}); // re-read second
    add_field_reference(1U, reference_at);
    code.insert(code.end(), {
        0x10b7U,          // xor-int/2addr v0, v1 => -1
        0x00d8U, 0x0100U, // add-int/lit8 v0, v0, #1 => 0
        0x0039U, 4U,      // if-nez v0, false
        0x1012U,          // const/4 v0, #1
        0x000fU,          // return v0
        0x0012U,          // false: const/4 v0, #0
        0x000fU,          // return v0
    });
    helper.direct_methods.push_back(std::move(method));
    return helper;
}


std::uint64_t ModelRuntimeBuilder::SourceShardSeed(const std::vector<dex::ClassSpec>& classes,
                              std::uint64_t seed) {
    auto shard_seed = utils::StableHash64("model-lowering-dex-shard", seed);
    for (const auto& klass : classes) {
        shard_seed = utils::StableHash64(klass.descriptor, shard_seed);
        shard_seed = utils::StableHash64(
            std::to_string(klass.direct_methods.size()) + ":" +
                std::to_string(klass.virtual_methods.size()) + ":" +
                std::to_string(klass.static_fields.size()) + ":" +
                std::to_string(klass.instance_fields.size()),
            shard_seed);
    }
    return shard_seed;
}


} // namespace birch::guard::detail
