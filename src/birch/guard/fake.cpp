#include "birch/guard/fake.h"

#include "birch/utils/hash.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace birch::guard {
namespace {

std::uint64_t Mix(std::uint64_t seed, std::string_view tag,
                  std::uint32_t class_index, std::uint32_t member_index = 0U) {
    auto mixed = utils::StableHash64(tag, seed);
    mixed ^= static_cast<std::uint64_t>(class_index) * 0x9e3779b97f4a7c15ULL;
    mixed ^= static_cast<std::uint64_t>(member_index) * 0xbf58476d1ce4e5b9ULL;
    mixed ^= mixed >> 30U;
    mixed *= 0xbf58476d1ce4e5b9ULL;
    mixed ^= mixed >> 27U;
    mixed *= 0x94d049bb133111ebULL;
    return mixed ^ (mixed >> 31U);
}

std::string HexName(std::string_view prefix, std::uint64_t value) {
    std::ostringstream stream;
    stream << prefix << std::hex << std::setfill('0') << std::setw(16) << value;
    return stream.str();
}

std::string ClassDescriptor(const FakeClassOptions& options,
                            std::uint32_t class_index) {
    return options.package_prefix +
           HexName("C", Mix(options.seed, "fake-class", class_index)).substr(0U, 10U) +
           ";";
}

std::string MethodName(std::uint64_t seed, std::uint32_t class_index,
                       std::uint32_t method_index) {
    return HexName("m", Mix(seed, "fake-method", class_index, method_index)).substr(0U, 11U);
}

std::string FieldName(std::uint64_t seed, std::uint32_t class_index,
                      std::uint32_t field_index) {
    return HexName("f", Mix(seed, "fake-field", class_index, field_index)).substr(0U, 11U);
}

std::string AnchorName(std::uint64_t seed, std::uint32_t class_index) {
    return HexName("a", Mix(seed, "fake-anchor", class_index)).substr(0U, 11U);
}

enum class FakeArchetype : std::uint8_t {
    Stateful,
    ArrayCarrier,
    StaticUtility,
    MarkerInterface,
};

FakeArchetype Archetype(std::uint32_t class_index) {
    switch (class_index % 16U) {
        case 13U: return FakeArchetype::ArrayCarrier;
        case 14U: return FakeArchetype::StaticUtility;
        case 15U: return FakeArchetype::MarkerInterface;
        default: return FakeArchetype::Stateful;
    }
}

std::uint32_t NextCallableClass(std::uint32_t class_index,
                                std::uint32_t class_count) {
    for (std::uint32_t distance = 1U; distance <= class_count; ++distance) {
        const auto candidate = (class_index + distance) % class_count;
        const auto archetype = Archetype(candidate);
        if (archetype != FakeArchetype::StaticUtility &&
            archetype != FakeArchetype::MarkerInterface) {
            return candidate;
        }
    }
    return class_index;
}

void AppendConst4(dex::MethodBodySpec& body, std::uint16_t reg,
                  std::uint16_t literal) {
    body.code_units.push_back(static_cast<std::uint16_t>(
        0x0012U | ((literal & 0x0fU) << 12U) | (reg << 8U)));
}

void AppendConst16(dex::MethodBodySpec& body, std::uint16_t reg,
                   std::uint16_t literal) {
    body.code_units.push_back(static_cast<std::uint16_t>(0x0013U | (reg << 8U)));
    body.code_units.push_back(literal);
}

void AppendIfEq(dex::MethodBodySpec& body, std::uint16_t a, std::uint16_t b,
                std::uint16_t offset) {
    body.code_units.push_back(static_cast<std::uint16_t>(0x0032U | (a << 8U) | (b << 12U)));
    body.code_units.push_back(offset);
}

void AppendIGet(dex::MethodBodySpec& body, const dex::FieldReference& field,
                std::uint16_t dest, std::uint16_t object) {
    const auto offset = static_cast<std::uint32_t>(body.code_units.size());
    body.code_units.push_back(static_cast<std::uint16_t>(0x0052U | (dest << 8U) | (object << 12U)));
    body.code_units.push_back(0U);
    body.references.push_back({field, offset + 1U, false});
}

void AppendIPut(dex::MethodBodySpec& body, const dex::FieldReference& field,
                std::uint16_t src, std::uint16_t object) {
    const auto offset = static_cast<std::uint32_t>(body.code_units.size());
    body.code_units.push_back(static_cast<std::uint16_t>(0x0059U | (src << 8U) | (object << 12U)));
    body.code_units.push_back(0U);
    body.references.push_back({field, offset + 1U, false});
}

void AppendConstString(dex::MethodBodySpec& body, std::uint16_t dest,
                       std::string value) {
    const auto offset = static_cast<std::uint32_t>(body.code_units.size());
    body.code_units.push_back(static_cast<std::uint16_t>(0x001aU | (dest << 8U)));
    body.code_units.push_back(0U);
    body.string_references.push_back({std::move(value), offset + 1U});
}

std::uint16_t ParameterWords(const std::vector<std::string>& parameters) {
    std::uint32_t words = 0U;
    for (const auto& descriptor : parameters) {
        if (descriptor.empty() || descriptor == "V") {
            throw std::invalid_argument("fake call target has an invalid parameter type");
        }
        words += descriptor == "J" || descriptor == "D" ? 2U : 1U;
    }
    if (words > 5U) throw std::invalid_argument("fake call target exceeds invoke-static 35c arguments");
    return static_cast<std::uint16_t>(words);
}

void AppendFakeInvoke(dex::MethodBodySpec& body,
                      const dex::MethodBodySpec::MethodReference& target,
                      std::uint16_t& max_words) {
    const auto words = ParameterWords(target.parameter_types);
    max_words = std::max(max_words, words);
    std::uint16_t next_register = 1U;
    for (const auto& descriptor : target.parameter_types) {
        if (descriptor == "J" || descriptor == "D") {
            body.code_units.push_back(static_cast<std::uint16_t>(0x0016U |
                                      (next_register << 8U)));
            body.code_units.push_back(0U);
            next_register = static_cast<std::uint16_t>(next_register + 2U);
        } else {
            body.code_units.push_back(static_cast<std::uint16_t>(0x0012U |
                                      (next_register << 8U)));
            ++next_register;
        }
    }
    std::uint16_t registers = 0U;
    for (std::uint16_t i = 0U; i < std::min<std::uint16_t>(words, 4U); ++i) {
        registers = static_cast<std::uint16_t>(registers | ((i + 1U) << (i * 4U)));
    }
    const auto fifth = words == 5U ? 5U : 0U;
    const auto invoke_offset = static_cast<std::uint32_t>(body.code_units.size());
    body.code_units.push_back(static_cast<std::uint16_t>(0x0071U |
                              (fifth << 8U) | (words << 12U)));
    body.code_units.push_back(0U);
    body.code_units.push_back(registers);
    body.invoke_references.push_back({target, invoke_offset + 1U});
}

void BuildStaticBody(dex::MethodSpec& method, std::uint64_t seed,
                     std::uint32_t class_index, std::uint32_t method_index,
                     const std::vector<dex::MethodBodySpec::MethodReference>& targets) {
    method.access_flags = 0x1009U; // public static synthetic
    method.body.registers_size = 6U;
    method.body.ins_size = 0U;
    method.body.outs_size = 0U;
    AppendConst4(method.body, 0U, static_cast<std::uint16_t>(Mix(seed, "a", class_index, method_index) & 0x7U));
    AppendConst4(method.body, 1U, static_cast<std::uint16_t>((Mix(seed, "b", class_index, method_index) & 0x7U) + 1U));
    method.body.code_units.push_back(0xb0U | (0U << 8U) | (1U << 12U)); // add-int/2addr v0, v1
    method.body.code_units.push_back(0xd8U | (0U << 8U) | (0U << 12U)); // add-int/lit8 v0, v0, #lit
    method.body.code_units.push_back(static_cast<std::uint16_t>(
        (Mix(seed, "lit", class_index, method_index) & 0x7fU) << 8U));
    const auto branch_offset = static_cast<std::uint32_t>(method.body.code_units.size());
    AppendIfEq(method.body, 0U, 1U, 1U);
    std::uint16_t max_words = 0U;
    for (const auto& target : targets) AppendFakeInvoke(method.body, target, max_words);
    method.body.outs_size = max_words;
    method.body.registers_size = std::max<std::uint16_t>(method.body.registers_size,
                                                         static_cast<std::uint16_t>(1U + max_words));
    const auto return_offset = static_cast<std::uint32_t>(method.body.code_units.size());
    if (return_offset <= branch_offset || return_offset - branch_offset > 0x7fffU) {
        throw std::length_error("fake method opaque branch exceeds int16 range");
    }
    method.body.code_units[branch_offset + 1U] =
        static_cast<std::uint16_t>(return_offset - branch_offset);
    method.body.code_units.push_back(0x000eU);
}

void BuildInstanceBody(dex::MethodSpec& method, std::uint64_t seed,
                       std::uint32_t class_index, std::uint32_t method_index,
                       std::string owner, std::string field_name) {
    method.access_flags = 0x0001U; // public virtual
    method.return_type = "I";
    method.body.registers_size = 4U;
    method.body.ins_size = 1U;
    method.body.outs_size = 0U;
    const dex::FieldReference field{std::move(owner), std::move(field_name), "I"};
    AppendIGet(method.body, field, 0U, 3U);
    AppendConst16(method.body, 1U, static_cast<std::uint16_t>(Mix(seed, "ivar", class_index, method_index)));
    method.body.code_units.push_back(0xb5U | (0U << 8U) | (1U << 12U)); // xor-int/2addr v0, v1
    method.body.code_units.push_back(0xd8U | (0U << 8U) | (0U << 12U)); // add-int/lit8 v0, v0, #lit
    method.body.code_units.push_back(static_cast<std::uint16_t>(
        (Mix(seed, "iadd", class_index, method_index) & 0x7fU) << 8U));
    AppendIPut(method.body, field, 0U, 3U);
    method.body.code_units.push_back(0x000fU | (0U << 8U)); // return v0
}

void BuildStringNoiseBody(dex::MethodSpec& method, std::uint64_t seed,
                          std::uint32_t class_index, std::uint32_t method_index) {
    method.access_flags = 0x1009U; // public static synthetic
    method.return_type = "Ljava/lang/String;";
    method.body.registers_size = 2U;
    method.body.ins_size = 0U;
    method.body.outs_size = 0U;
    AppendConstString(method.body, 0U,
                      HexName("z", Mix(seed, "fake-string", class_index, method_index)));
    AppendConst4(method.body, 1U, static_cast<std::uint16_t>(Mix(seed, "string-pred", class_index, method_index) & 0x7U));
    const auto branch_offset = static_cast<std::uint32_t>(method.body.code_units.size());
    AppendIfEq(method.body, 1U, 1U, 1U);
    AppendConstString(method.body, 0U,
                      HexName("q", Mix(seed, "fake-dead-string", class_index, method_index)));
    const auto return_offset = static_cast<std::uint32_t>(method.body.code_units.size());
    method.body.code_units[branch_offset + 1U] =
        static_cast<std::uint16_t>(return_offset - branch_offset);
    method.body.code_units.push_back(0x0011U | (0U << 8U)); // return-object v0
}

void BuildSensitiveApiNoiseBody(dex::MethodSpec& method, std::uint64_t seed,
                                std::uint32_t class_index,
                                std::string_view owner) {
    method.name = HexName(
        "r", Mix(seed, "fake-sensitive", class_index)).substr(0U, 11U);
    method.access_flags = 0x1009U; // public static synthetic
    method.return_type = "V";
    method.body.registers_size = 4U;
    method.body.outs_size = 3U;

    const auto class_reference = static_cast<std::uint32_t>(
        method.body.code_units.size());
    method.body.code_units.insert(method.body.code_units.end(), {
        0x031cU, 0U,             // const-class v3, owner
        0x1071U, 0U, 0x0003U,   // System.identityHashCode(v3)
        0x030aU,                 // move-result v3
    });
    method.body.references.push_back({
        dex::TypeReference{std::string(owner)}, class_reference + 1U, false});
    method.body.invoke_references.push_back({
        dex::MethodReference{"Ljava/lang/System;", "identityHashCode", "I",
                             {"Ljava/lang/Object;"}},
        class_reference + 3U});

    const auto append_runtime_relation = [&](std::uint8_t key) {
        method.body.code_units.push_back(0x3201U); // move v2, v3
        method.body.code_units.insert(method.body.code_units.end(), {
            0x02dfU, static_cast<std::uint16_t>(2U | (key << 8U)),
            0x02dfU, static_cast<std::uint16_t>(2U | (key << 8U)),
        });
    };

    AppendConstString(method.body, 0U, "java.lang.String");
    append_runtime_relation(static_cast<std::uint8_t>(
        Mix(seed, "fake-reflection-guard", class_index) | 1U));
    const auto reflection_branch = static_cast<std::uint32_t>(
        method.body.code_units.size());
    AppendIfEq(method.body, 2U, 3U, 1U);
    const auto reflection_invoke = static_cast<std::uint32_t>(
        method.body.code_units.size());
    method.body.code_units.insert(method.body.code_units.end(), {
        0x1071U, 0U, 0x0000U}); // Class.forName(v0)
    method.body.invoke_references.push_back({
        dex::MethodReference{"Ljava/lang/Class;", "forName",
                             "Ljava/lang/Class;", {"Ljava/lang/String;"}},
        reflection_invoke + 1U});
    const auto after_reflection = static_cast<std::uint32_t>(
        method.body.code_units.size());
    method.body.code_units[reflection_branch + 1U] =
        static_cast<std::uint16_t>(after_reflection - reflection_branch);

    AppendConstString(method.body, 0U,
                      "birch/" + HexName(
                          "p", Mix(seed, "fake-dex-path", class_index)) + ".dex");
    AppendConstString(method.body, 1U,
                      "birch/" + HexName(
                          "o", Mix(seed, "fake-odex-path", class_index)) + ".odex");
    append_runtime_relation(static_cast<std::uint8_t>(
        Mix(seed, "fake-loader-guard", class_index) | 1U));
    const auto loading_branch = static_cast<std::uint32_t>(
        method.body.code_units.size());
    AppendIfEq(method.body, 2U, 3U, 1U);
    const auto loading_invoke = static_cast<std::uint32_t>(
        method.body.code_units.size());
    method.body.code_units.insert(method.body.code_units.end(), {
        0x3071U, 0U, 0x0210U}); // DexFile.loadDex(v0,v1,v2)
    method.body.invoke_references.push_back({
        dex::MethodReference{
            "Ldalvik/system/DexFile;", "loadDex", "Ldalvik/system/DexFile;",
            {"Ljava/lang/String;", "Ljava/lang/String;", "I"}},
        loading_invoke + 1U});
    const auto return_offset = static_cast<std::uint32_t>(
        method.body.code_units.size());
    method.body.code_units[loading_branch + 1U] =
        static_cast<std::uint16_t>(return_offset - loading_branch);
    method.body.code_units.push_back(0x000eU);
}

void BuildSwitchBody(dex::MethodSpec& method, std::uint64_t seed,
                     std::uint32_t class_index, std::uint32_t method_index) {
    method.return_type = "I";
    method.access_flags = 0x1009U; // public static synthetic
    method.body.registers_size = 1U;
    method.body.ins_size = 0U;
    method.body.outs_size = 0U;
    const auto key = static_cast<std::uint16_t>(
        Mix(seed, "fake-switch", class_index, method_index) & 1U);
    method.body.code_units = {
        static_cast<std::uint16_t>(0x0012U | (key << 12U)),
        0x002bU, 9U, 0U,
        0x3012U, 0x000fU,
        0x1012U, 0x000fU,
        0x2012U, 0x000fU,
        0x0100U, 2U, 0U, 0U,
        5U, 0U, 7U, 0U,
    };
}

void AddInlinePair(dex::ClassSpec& klass, std::uint64_t seed,
                   std::uint32_t class_index) {
    dex::MethodSpec constant;
    constant.name = HexName(
        "i", Mix(seed, "fake-inline-target", class_index)).substr(0U, 11U);
    constant.return_type = "I";
    constant.access_flags = 0x100aU; // private static synthetic
    constant.body.registers_size = 1U;
    const auto literal = static_cast<std::uint16_t>(
        Mix(seed, "fake-inline-value", class_index) & 7U);
    constant.body.code_units = {
        static_cast<std::uint16_t>(0x0012U | (literal << 12U)), 0x000fU};

    dex::MethodSpec caller;
    caller.name = HexName(
        "j", Mix(seed, "fake-inline-caller", class_index)).substr(0U, 11U);
    caller.return_type = "I";
    caller.access_flags = 0x1009U; // public static synthetic
    caller.body.registers_size = 1U;
    caller.body.outs_size = 0U;
    caller.body.code_units = {0x0071U, 0U, 0U, 0x000aU, 0x000fU};
    caller.body.references.push_back({
        dex::MethodReference{klass.descriptor, constant.name, "I", {}},
        1U, false});
    klass.direct_methods.push_back(std::move(constant));
    klass.direct_methods.push_back(std::move(caller));
}

void AddTailLoop(dex::ClassSpec& klass, std::uint64_t seed,
                 std::uint32_t class_index) {
    dex::MethodSpec loop;
    loop.name = HexName("t", Mix(seed, "fake-tail-loop", class_index)).substr(0U, 11U);
    loop.return_type = "I";
    loop.parameter_types = {"I"};
    loop.access_flags = 0x1009U;
    loop.body.registers_size = 1U;
    loop.body.ins_size = 1U;
    loop.body.code_units = {
        0x003dU, 6U,       // if-lez p0, return
        0x00d8U, 0xff00U, // add-int/lit8 p0, p0, #-1
        0x0029U, 0xfffcU, // goto/16 loop header
        0x000fU,           // return p0
    };
    klass.direct_methods.push_back(std::move(loop));
}

void AddEnumPair(dex::DexBuilder& builder, const FakeClassOptions& options,
                 std::uint32_t class_index) {
    const auto enum_descriptor = ClassDescriptor(options, class_index);
    const auto user_descriptor = ClassDescriptor(options, class_index + 1U);

    dex::ClassSpec enum_class;
    enum_class.descriptor = enum_descriptor;
    enum_class.access_flags = 0x4011U;
    enum_class.superclass = "Ljava/lang/Enum;";
    dex::FieldSpec value;
    value.name = "VALUE";
    value.type = enum_descriptor;
    value.access_flags = 0x4019U;
    enum_class.static_fields.push_back(std::move(value));
    builder.AddClass(std::move(enum_class));

    dex::ClassSpec user;
    user.descriptor = user_descriptor;
    dex::MethodSpec compare;
    compare.name = "isFirst";
    compare.return_type = "I";
    compare.access_flags = 0x1009U;
    compare.body.registers_size = 2U;
    compare.body.outs_size = 1U;
    compare.body.code_units = {
        0x0062U, 0U,             // sget-object v0, VALUE
        0x106eU, 0U, 0x0000U,   // invoke-virtual {v0}, ordinal
        0x000aU,                 // move-result v0
        0x0112U,                 // const/4 v1, 0
        0x1033U, 3U,             // if-ne v0, v1, false
        0x0012U,                 // const/4 v0, 0
        0x000fU,                 // return v0
        0x1012U,                 // false: const/4 v0, 1
        0x000fU,                 // return v0
    };
    compare.body.references = {
        {dex::FieldReference{enum_descriptor, "VALUE", enum_descriptor}, 1U,
         false},
        {dex::MethodReference{"Ljava/lang/Enum;", "ordinal", "I", {}}, 3U,
         false},
    };
    user.direct_methods.push_back(std::move(compare));
    builder.AddClass(std::move(user));
}

void AddEncodedArray(dex::ClassSpec& klass, std::uint64_t seed,
                     std::uint32_t class_index) {
    const auto field_name = FieldName(seed, class_index, 2U);
    dex::FieldSpec field;
    field.name = field_name;
    field.type = "[I";
    field.access_flags = 0x101aU; // private static final synthetic
    klass.static_fields.push_back(std::move(field));

    dex::MethodSpec initializer;
    initializer.name = "<clinit>";
    initializer.return_type = "V";
    initializer.access_flags = 0x10008U; // static constructor
    initializer.body.registers_size = 1U;
    initializer.body.code_units = {
        0x0013U, 8U,       // const/16 v0, #8
        0x0023U, 0U,       // new-array v0, v0, [I
        0x0026U, 6U, 0U,   // fill-array-data v0, payload@10
        0x0069U, 0U,       // sput-object v0, field
        0x000eU,           // return-void
        0x0300U, 4U, 8U, 0U,
    };
    initializer.body.references.push_back(
        {dex::TypeReference{"[I"}, 3U, false});
    initializer.body.references.push_back(
        {dex::FieldReference{klass.descriptor, field_name, "[I"}, 8U, false});
    for (std::uint32_t index = 0U; index < 8U; ++index) {
        const auto value = static_cast<std::uint32_t>(
            Mix(seed, "fake-array", class_index, index));
        initializer.body.code_units.push_back(
            static_cast<std::uint16_t>(value));
        initializer.body.code_units.push_back(
            static_cast<std::uint16_t>(value >> 16U));
    }
    klass.direct_methods.push_back(std::move(initializer));

    dex::MethodSpec getter;
    getter.name = HexName(
        "g", Mix(seed, "fake-array-get", class_index)).substr(0U, 11U);
    getter.return_type = "I";
    getter.parameter_types = {"I"};
    getter.access_flags = 0x1009U;
    getter.body.registers_size = 2U;
    getter.body.ins_size = 1U;
    getter.body.code_units = {
        0x0062U, 0U,       // sget-object v0, field
        0x0044U, 0x0100U, // aget v0, v0, p0
        0x000fU,
    };
    getter.body.references.push_back({
        dex::FieldReference{klass.descriptor, field_name, "[I"}, 1U, false});
    klass.direct_methods.push_back(std::move(getter));
}

} // namespace

std::vector<std::uint8_t> BuildFakeDex(const FakeClassOptions& options) {
    if (options.class_count == 0U || options.methods_per_class == 0U || options.class_count > 10000U || options.methods_per_class > 100U) {
        throw std::invalid_argument("fake class options exceed safety limits");
    }
    if (!std::isfinite(options.density) || options.density < 0.0 || options.density > 1.0) {
        throw std::invalid_argument("fake call density must be finite and in [0,1]");
    }
    // Use an exactly representable 53-bit sampling domain. UINT64_MAX rounds
    // to 2^64 in double, so converting density * double(UINT64_MAX) is UB at
    // the default density 1.0 and can silently suppress every generated call.
    const auto density_threshold = static_cast<std::uint64_t>(options.density * 0x1p53);
    dex::DexBuilder builder(options.dex_version);
    std::vector<std::string> descriptors;
    descriptors.reserve(options.class_count);
    for (std::uint32_t i = 0; i < options.class_count; ++i) {
        descriptors.push_back(ClassDescriptor(options, i));
    }
    for (std::uint32_t class_index = 0; class_index < options.class_count; ++class_index) {
        dex::ClassSpec klass;
        klass.descriptor = descriptors[class_index];
        const auto archetype = Archetype(class_index);
        klass.access_flags = archetype == FakeArchetype::MarkerInterface ?
            0x0601U : 0x0001U;
        klass.source_file = HexName("S", Mix(options.seed, "fake-source", class_index)).substr(0U, 13U);
        if (archetype == FakeArchetype::MarkerInterface) {
            builder.AddClass(std::move(klass));
            continue;
        }
        if (archetype != FakeArchetype::StaticUtility && class_index != 0U &&
            (Mix(options.seed, "fake-super", class_index) & 3U) == 0U) {
            const auto candidate = static_cast<std::uint32_t>(
                Mix(options.seed, "fake-super-pick", class_index) % class_index);
            if (Archetype(candidate) == FakeArchetype::Stateful) {
                klass.superclass = descriptors[candidate];
            }
        }
        if (archetype == FakeArchetype::Stateful &&
            (Mix(options.seed, "fake-interface", class_index) & 7U) == 0U) {
            klass.interfaces.push_back("Ljava/lang/Runnable;");
            dex::MethodSpec run;
            run.name = "run";
            run.access_flags = 0x0001U;
            run.body.registers_size = 1U;
            run.body.ins_size = 1U;
            run.body.code_units = {0x000eU};
            klass.virtual_methods.push_back(std::move(run));
        }
        const auto field_name = FieldName(options.seed, class_index, 0U);
        if (archetype != FakeArchetype::StaticUtility) {
            dex::FieldSpec instance_field;
            instance_field.name = field_name;
            instance_field.type = "I";
            instance_field.access_flags = 0x0001U;
            klass.instance_fields.push_back(std::move(instance_field));
            dex::FieldSpec static_field;
            static_field.name = FieldName(options.seed, class_index, 1U);
            static_field.type = "I";
            static_field.access_flags = 0x0009U;
            klass.static_fields.push_back(std::move(static_field));
        }
        dex::MethodSpec anchor;
        anchor.name = AnchorName(options.seed, class_index);
        anchor.access_flags = 0x1009U; // public static synthetic
        anchor.body.registers_size = 1U;
        anchor.body.ins_size = 0U;
        anchor.body.outs_size = 0U;
        anchor.body.code_units = {0x000eU};
        klass.direct_methods.push_back(std::move(anchor));
        AddInlinePair(klass, options.seed, class_index);
        if (options.class_count >= 8U && (class_index % 8U) == 0U) {
            AddTailLoop(klass, options.seed, class_index);
        }
        if ((class_index % 8U) == 0U) {
            dex::MethodSpec sensitive;
            BuildSensitiveApiNoiseBody(
                sensitive, options.seed, class_index, klass.descriptor);
            klass.direct_methods.push_back(std::move(sensitive));
        }
        if (archetype == FakeArchetype::ArrayCarrier) {
            AddEncodedArray(klass, options.seed, class_index);
        }
        for (std::uint32_t method_index = 0; method_index < options.methods_per_class; ++method_index) {
            dex::MethodSpec method;
            method.name = MethodName(options.seed, class_index, method_index);
            const auto variant = method_index == 0U ? 0U :
                static_cast<std::uint32_t>(Mix(
                    options.seed, "fake-variant", class_index,
                    method_index) % 4U);
            if (variant == 1U && archetype != FakeArchetype::StaticUtility) {
                BuildInstanceBody(method, options.seed, class_index, method_index,
                                  klass.descriptor, field_name);
                klass.virtual_methods.push_back(std::move(method));
                continue;
            }
            if (variant == 2U) {
                BuildStringNoiseBody(method, options.seed, class_index, method_index);
                klass.direct_methods.push_back(std::move(method));
                continue;
            }
            if (variant == 3U) {
                BuildSwitchBody(method, options.seed, class_index, method_index);
                klass.direct_methods.push_back(std::move(method));
                continue;
            }
            if (options.invoke_real_method ||
                (Mix(options.seed, "fake-call-density", class_index, method_index) >> 11U) < density_threshold) {
                std::vector<dex::MethodBodySpec::MethodReference> targets;
                const auto target_class = NextCallableClass(
                    class_index, options.class_count);
                targets.push_back({
                    descriptors[target_class],
                    AnchorName(options.seed, target_class),
                    "V", {}});
                if (!options.real_targets.empty()) {
                    const auto mixed_seed = options.seed ^
                        (static_cast<std::uint64_t>(class_index) << 32U) ^ method_index;
                    targets.push_back(options.real_targets[mixed_seed % options.real_targets.size()]);
                } else {
                    targets.push_back({"Ljava/lang/System;", "gc", "V", {}});
                }
                BuildStaticBody(method, options.seed, class_index, method_index, targets);
            } else {
                method.body.registers_size = 1U;
                method.body.code_units = {0x1012U, 0x000eU};
            }
            klass.direct_methods.push_back(std::move(method));
        }
        builder.AddClass(std::move(klass));
    }
    if (options.class_count >= 8U) {
        AddEnumPair(builder, options, options.class_count);
    }
    return builder.Build();
}

} // namespace birch::guard
