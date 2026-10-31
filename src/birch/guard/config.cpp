#include "birch/guard/config.h"

#include "rename_names.h"

#include "birch/guard/json.h"
#include "birch/utils/hash.h"

#include <algorithm>
#include <chrono>
#include <charconv>
#include <cmath>
#include <limits>
#include <random>
#include <stdexcept>

namespace birch::guard {
namespace {

using json::Value;

const Value& Required(const Value::Object& object, std::string_view key) {
    const auto found = object.find(key);
    if (found == object.end()) {
        throw std::invalid_argument("missing required config key: " + std::string(key));
    }
    return found->second;
}

const Value* Optional(const Value::Object& object, std::string_view key) {
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &found->second;
}

std::uint64_t AsUnsigned(const Value& value, std::string_view key) {
    // JSON numbers are doubles. Beyond this bound an integer may already
    // have been rounded, and 2^64 must never reach a float-to-integer cast.
    if (!value.is_number() || !std::isfinite(value.as_number()) || value.as_number() < 0.0 ||
        std::floor(value.as_number()) != value.as_number() ||
        value.as_number() > 9007199254740991.0) {
        throw std::invalid_argument("config key must be an exactly representable non-negative integer: " + std::string(key));
    }
    return static_cast<std::uint64_t>(value.as_number());
}

std::uint64_t AsSeed(const Value& value, std::string_view key) {
    if (!value.is_string()) return AsUnsigned(value, key);
    const auto& raw = value.as_string();
    std::uint64_t result{};
    const auto parsed = std::from_chars(raw.data(), raw.data() + raw.size(), result);
    if (raw.empty() || parsed.ec != std::errc{} || parsed.ptr != raw.data() + raw.size())
        throw std::invalid_argument("config seed must be decimal uint64: " + std::string(key));
    return result;
}

std::uint32_t AsUnsigned32(const Value& value, std::string_view key) {
    const auto result = AsUnsigned(value, key);
    if (result > std::numeric_limits<std::uint32_t>::max())
        throw std::invalid_argument("config integer exceeds uint32: " + std::string(key));
    return static_cast<std::uint32_t>(result);
}

double AsFiniteNumber(const Value& value, std::string_view key) {
    if (!value.is_number() || !std::isfinite(value.as_number())) {
        throw std::invalid_argument("config key must be a finite number: " + std::string(key));
    }
    return value.as_number();
}

bool AsBool(const Value& value, std::string_view key) {
    if (!value.is_bool()) {
        throw std::invalid_argument("config key must be boolean: " + std::string(key));
    }
    return value.as_bool();
}

std::string AsString(const Value& value, std::string_view key) {
    if (!value.is_string()) {
        throw std::invalid_argument("config key must be string: " + std::string(key));
    }
    return value.as_string();
}

void RejectUnknown(const Value::Object& object,
                   std::initializer_list<std::string_view> known,
                   std::string_view scope) {
    for (const auto& [key, unused] : object) {
        (void)unused;
        if (std::find(known.begin(), known.end(), key) == known.end()) {
            throw std::invalid_argument("unknown config key " + std::string(scope) + "." + key);
        }
    }
}

PassConfig ParsePass(const Value& value, const PassDescriptor& descriptor,
                     std::string_view id) {
    if (!value.is_object()) {
        throw std::invalid_argument("pass config must be an object: " + std::string(id));
    }
    const auto& object = value.as_object();
    RejectUnknown(object, {"enabled", "intensity", "seed", "max_applications_per_method"}, id);
    PassConfig result{descriptor.default_enabled, descriptor.default_intensity, std::nullopt,
                      std::nullopt};
    if (const auto* item = Optional(object, "enabled")) result.enabled = AsBool(*item, "enabled");
    if (const auto* item = Optional(object, "intensity")) result.intensity = AsFiniteNumber(*item, "intensity");
    if (const auto* item = Optional(object, "seed")) result.seed = AsSeed(*item, "seed");
    if (const auto* item = Optional(object, "max_applications_per_method")) {
        const auto raw = AsUnsigned(*item, "max_applications_per_method");
        if (raw > std::numeric_limits<std::uint32_t>::max()) {
            throw std::invalid_argument("max_applications_per_method is too large");
        }
        result.max_applications_per_method = static_cast<std::uint32_t>(raw);
    }
    return result;
}

void ParseRules(const Value* value, std::vector<ScopeRule>& output, std::string_view key) {
    if (value == nullptr) return;
    if (!value->is_array()) throw std::invalid_argument(std::string(key) + " must be an array");
    for (const auto& item : value->as_array()) {
        if (!item.is_object()) throw std::invalid_argument("scope rule must be an object");
        const auto& object = item.as_object();
        RejectUnknown(object, {"pattern", "include_members", "allow_renaming", "allow_code_transforms"}, key);
        ScopeRule rule{AsString(Required(object, "pattern"), "pattern"), true, true, true};
        if (const auto* v = Optional(object, "include_members")) rule.include_members = AsBool(*v, "include_members");
        if (const auto* v = Optional(object, "allow_renaming")) rule.allow_renaming = AsBool(*v, "allow_renaming");
        if (const auto* v = Optional(object, "allow_code_transforms")) rule.allow_code_transforms = AsBool(*v, "allow_code_transforms");
        output.push_back(std::move(rule));
    }
}

} // namespace

std::string DefaultRenameDictionary() {
    return "ۧ֫ܽ᩵᩺ᩳۤۖܳ᩷ܺ۫ܿܰۙۢ֨᩶֡۬۟ۛ᩸ۡۨ᩹ܶۜ᩻ۗۚۘᩴ۠";
}

std::uint64_t StrengthRandomizedSeed(const GuardConfig& config) {
    if (config.effective_seed) return *config.effective_seed;
    if (!config.strength.randomized_parameters ||
        !config.passes.at("strength.build_parameter_randomization").enabled) {
        return config.seed;
    }
    auto seed = utils::StableHash64("strength.build_parameter_randomization",
                                    config.seed ^ 0x5f6c6f7564ULL);
    seed = utils::StableHash64(config.rename.dictionary, seed);
    seed = utils::StableHash64(config.rename.package_prefix, seed);
    seed = utils::StableHash64(config.resources.dictionary, seed);
    seed = utils::StableHash64(config.fake.package_prefix, seed);
    seed = utils::StableHash64(
        std::to_string(config.fake.class_count) + ":" +
            std::to_string(config.fake.methods_per_class) + ":" +
            std::to_string(config.multidex.repartition) + ":" +
            std::to_string(config.multidex.preserve_input_order),
        seed);
    seed = utils::StableHash64(config.android_dex, seed);
    for (const auto& [id, pass] : config.passes) {
        if (!pass.enabled) continue;
        seed = utils::StableHash64(
            id + ":" + std::to_string(pass.intensity) + ":" +
                std::to_string(pass.enabled),
            seed ^ (pass.seed.value_or(config.seed) + 0x9e3779b97f4a7c15ULL));
    }
    if (!config.strength.reproducible_output) {
        std::random_device entropy;
        std::uint64_t runtime_entropy =
            static_cast<std::uint64_t>(entropy()) << 32U;
        runtime_entropy ^= static_cast<std::uint64_t>(entropy());
        runtime_entropy ^= static_cast<std::uint64_t>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count());
        runtime_entropy ^= static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count()) << 1U;
        seed = utils::StableHash64(std::to_string(runtime_entropy),
                                   seed ^ 0xa0761d6478bd642fULL);
    }
    return seed;
}

GuardConfig GuardConfig::Defaults() {
    GuardConfig result;
    result.rename.dictionary = DefaultRenameDictionary();
    for (const auto& descriptor : PassRegistry()) {
        result.passes.emplace(descriptor.id, PassConfig{descriptor.default_enabled,
                                                        descriptor.default_intensity,
                                                        std::nullopt, std::nullopt});
    }
    return result;
}

GuardConfig GuardConfig::Parse(std::string_view source) {
    const auto root = json::Parse(source);
    if (!root.is_object()) throw std::invalid_argument("root config must be an object");
    const auto& object = root.as_object();
    RejectUnknown(object, {"schema_version", "seed", "effective_seed", "android_dex", "scope", "budget", "rename", "multidex", "strength", "fake", "resources", "signing", "output", "passes"}, "root");
    auto result = Defaults();
    if (const auto* value = Optional(object, "schema_version")) result.schema_version = AsUnsigned32(*value, "schema_version");
    if (const auto* value = Optional(object, "seed")) result.seed = AsSeed(*value, "seed");
    if (const auto* value = Optional(object, "effective_seed")) result.effective_seed = AsSeed(*value, "effective_seed");
    if (const auto* value = Optional(object, "android_dex")) {
        result.android_dex = AsString(*value, "android_dex");
    }
    if (const auto* value = Optional(object, "scope")) {
        if (!value->is_object()) throw std::invalid_argument("scope must be object");
        RejectUnknown(value->as_object(), {"protect", "keep"}, "scope");
        ParseRules(Optional(value->as_object(), "protect"), result.scope.protect, "scope.protect");
        ParseRules(Optional(value->as_object(), "keep"), result.scope.keep, "scope.keep");
    }
    if (const auto* value = Optional(object, "budget")) {
        if (!value->is_object()) throw std::invalid_argument("budget must be object");
        const auto& budget = value->as_object();
        RejectUnknown(budget, {"max_code_units_per_method", "max_registers_per_method", "max_added_blocks_per_method", "max_added_try_regions_per_method", "max_method_growth_ratio", "max_dex_growth_ratio", "max_analysis_blocks_per_method", "max_call_depth_increase"}, "budget");
        if (const auto* v = Optional(budget, "max_code_units_per_method")) result.budget.max_code_units_per_method = AsUnsigned32(*v, "max_code_units_per_method");
        if (const auto* v = Optional(budget, "max_registers_per_method")) result.budget.max_registers_per_method = AsUnsigned32(*v, "max_registers_per_method");
        if (const auto* v = Optional(budget, "max_added_blocks_per_method")) result.budget.max_added_blocks_per_method = AsUnsigned32(*v, "max_added_blocks_per_method");
        if (const auto* v = Optional(budget, "max_added_try_regions_per_method")) result.budget.max_added_try_regions_per_method = AsUnsigned32(*v, "max_added_try_regions_per_method");
        if (const auto* v = Optional(budget, "max_method_growth_ratio")) result.budget.max_method_growth_ratio = AsFiniteNumber(*v, "max_method_growth_ratio");
        if (const auto* v = Optional(budget, "max_dex_growth_ratio")) result.budget.max_dex_growth_ratio = AsFiniteNumber(*v, "max_dex_growth_ratio");
        if (const auto* v = Optional(budget, "max_analysis_blocks_per_method")) result.budget.max_analysis_blocks_per_method = AsUnsigned32(*v, "max_analysis_blocks_per_method");
        if (const auto* v = Optional(budget, "max_call_depth_increase")) result.budget.max_call_depth_increase = AsUnsigned32(*v, "max_call_depth_increase");
    }
    if (const auto* value = Optional(object, "strength")) {
        if (!value->is_object()) throw std::invalid_argument("strength must be object");
        const auto& strength = value->as_object();
        RejectUnknown(strength, {"per_method_strategy", "randomized_parameters", "reproducible_output", "anti_automation_profile", "target_analysis_cost_weeks"}, "strength");
        if (const auto* v = Optional(strength, "per_method_strategy")) result.strength.per_method_strategy = AsBool(*v, "per_method_strategy");
        if (const auto* v = Optional(strength, "randomized_parameters")) result.strength.randomized_parameters = AsBool(*v, "randomized_parameters");
        if (const auto* v = Optional(strength, "reproducible_output")) result.strength.reproducible_output = AsBool(*v, "reproducible_output");
        if (const auto* v = Optional(strength, "anti_automation_profile")) result.strength.anti_automation_profile = AsBool(*v, "anti_automation_profile");
        if (const auto* v = Optional(strength, "target_analysis_cost_weeks")) result.strength.target_analysis_cost_weeks = AsUnsigned32(*v, "target_analysis_cost_weeks");
    }
    if (const auto* value = Optional(object, "fake")) {
        if (!value->is_object()) throw std::invalid_argument("fake must be object");
        const auto& fake = value->as_object();
        RejectUnknown(fake, {"package_prefix", "class_count", "methods_per_class"}, "fake");
        if (const auto* v = Optional(fake, "package_prefix")) result.fake.package_prefix = AsString(*v, "package_prefix");
        if (const auto* v = Optional(fake, "class_count")) result.fake.class_count = AsUnsigned32(*v, "class_count");
        if (const auto* v = Optional(fake, "methods_per_class")) result.fake.methods_per_class = AsUnsigned32(*v, "methods_per_class");
    }
    if (const auto* value = Optional(object, "resources")) {
        if (!value->is_object()) throw std::invalid_argument("resources must be object");
        const auto& resources = value->as_object();
        RejectUnknown(resources, {"rename_files", "rename_names", "dictionary"}, "resources");
        if (const auto* v = Optional(resources, "rename_files")) result.resources.rename_files = AsBool(*v, "rename_files");
        if (const auto* v = Optional(resources, "rename_names")) result.resources.rename_names = AsBool(*v, "rename_names");
        if (const auto* v = Optional(resources, "dictionary")) result.resources.dictionary = AsString(*v, "dictionary");
    }
    if (const auto* value = Optional(object, "signing")) {
        if (!value->is_object()) throw std::invalid_argument("signing must be object");
        const auto& signing = value->as_object();
        RejectUnknown(signing, {"enabled", "keystore", "alias"}, "signing");
        if (const auto* v = Optional(signing, "enabled")) result.signing.enabled = AsBool(*v, "enabled");
        if (const auto* v = Optional(signing, "keystore")) result.signing.keystore = AsString(*v, "keystore");
        if (const auto* v = Optional(signing, "alias")) result.signing.alias = AsString(*v, "alias");
    }
    if (const auto* value = Optional(object, "output")) {
        if (!value->is_object()) throw std::invalid_argument("output must be object");
        const auto& output = value->as_object();
        RejectUnknown(output, {"mapping_file", "write_mapping"}, "output");
        if (const auto* v = Optional(output, "mapping_file")) result.output.mapping_file = AsString(*v, "mapping_file");
        if (const auto* v = Optional(output, "write_mapping")) result.output.write_mapping = AsBool(*v, "write_mapping");
    }
    if (const auto* value = Optional(object, "rename")) {
        if (!value->is_object()) throw std::invalid_argument("rename must be object");
        const auto& rename = value->as_object();
        RejectUnknown(rename, {"dictionary", "package_prefix", "overload_methods", "rename_source_files"}, "rename");
        if (const auto* v = Optional(rename, "dictionary")) result.rename.dictionary = AsString(*v, "dictionary");
        if (const auto* v = Optional(rename, "package_prefix")) result.rename.package_prefix = AsString(*v, "package_prefix");
        if (const auto* v = Optional(rename, "overload_methods")) result.rename.overload_methods = AsBool(*v, "overload_methods");
        if (const auto* v = Optional(rename, "rename_source_files")) result.rename.rename_source_files = AsBool(*v, "rename_source_files");
    }
    if (const auto* value = Optional(object, "multidex")) {
        if (!value->is_object()) throw std::invalid_argument("multidex must be object");
        const auto& multidex = value->as_object();
        RejectUnknown(multidex, {"limits", "repartition", "preserve_input_order", "primary_dex_classes"}, "multidex");
        if (const auto* v = Optional(multidex, "repartition")) result.multidex.repartition = AsBool(*v, "repartition");
        if (const auto* v = Optional(multidex, "preserve_input_order")) result.multidex.preserve_input_order = AsBool(*v, "preserve_input_order");
        if (const auto* v = Optional(multidex, "primary_dex_classes")) {
            if (!v->is_array()) throw std::invalid_argument("primary_dex_classes must be array");
            for (const auto& item : v->as_array()) result.multidex.primary_dex_classes.push_back(AsString(item, "primary_dex_classes"));
        }
        if (const auto* v = Optional(multidex, "limits")) {
            if (!v->is_object()) throw std::invalid_argument("multidex.limits must be object");
            const auto& limits = v->as_object();
            RejectUnknown(limits, {"strings", "types", "protos", "fields", "methods", "call_sites", "method_handles"}, "multidex.limits");
            if (const auto* x = Optional(limits, "strings")) result.multidex.limits.strings = AsUnsigned32(*x, "strings");
            if (const auto* x = Optional(limits, "types")) result.multidex.limits.types = AsUnsigned32(*x, "types");
            if (const auto* x = Optional(limits, "protos")) result.multidex.limits.protos = AsUnsigned32(*x, "protos");
            if (const auto* x = Optional(limits, "fields")) result.multidex.limits.fields = AsUnsigned32(*x, "fields");
            if (const auto* x = Optional(limits, "methods")) result.multidex.limits.methods = AsUnsigned32(*x, "methods");
            if (const auto* x = Optional(limits, "call_sites")) result.multidex.limits.call_sites = AsUnsigned32(*x, "call_sites");
            if (const auto* x = Optional(limits, "method_handles")) result.multidex.limits.method_handles = AsUnsigned32(*x, "method_handles");
        }
    }
    if (const auto* value = Optional(object, "passes")) {
        if (!value->is_object()) throw std::invalid_argument("passes must be object");
        for (const auto& [id, pass] : value->as_object()) {
            const auto* descriptor = FindPass(id);
            if (descriptor == nullptr) throw std::invalid_argument("unknown pass: " + id);
            result.passes[id] = ParsePass(pass, *descriptor, id);
        }
    }
    result.Validate();
    return result;
}

void GuardConfig::Validate() const {
    if (schema_version != 1U) throw std::invalid_argument("unsupported config schema_version");
    // Validate before lowering rather than allowing malformed bytes into DEX names.
    (void)detail::NameGenerator::DictionaryTokens(rename.dictionary);
    if (!resources.dictionary.empty()) {
        (void)detail::NameGenerator::DictionaryTokens(resources.dictionary);
        for (const auto character : resources.dictionary) {
            if (static_cast<unsigned char>(character) < 0x20U ||
                std::string_view("\\/:*?\"<>|-").find(character) != std::string_view::npos) {
                throw std::invalid_argument("resources.dictionary contains unsafe filename characters");
            }
        }
    }
    if (signing.enabled && (signing.keystore.empty() || signing.alias.empty())) {
        throw std::invalid_argument("signing requires keystore and alias");
    }
    if (fake.package_prefix.empty() || fake.package_prefix.front() != 'L' || fake.package_prefix.back() != '/') {
        throw std::invalid_argument("fake.package_prefix must be a descriptor package prefix");
    }
    if (fake.class_count == 0U || fake.class_count > 10000U || fake.methods_per_class == 0U || fake.methods_per_class > 100U) {
        throw std::invalid_argument("fake class counts are outside safety limits");
    }
    if (rename.package_prefix.empty() || rename.package_prefix.front() != 'b') {
        throw std::invalid_argument("rename.package_prefix must begin with b");
    }
    if (budget.max_code_units_per_method == 0U || budget.max_registers_per_method == 0U ||
        budget.max_added_blocks_per_method == 0U || !std::isfinite(budget.max_method_growth_ratio) ||
        !std::isfinite(budget.max_dex_growth_ratio) || budget.max_method_growth_ratio < 1.0 ||
        budget.max_dex_growth_ratio < 1.0 || budget.max_analysis_blocks_per_method == 0U) {
        throw std::invalid_argument("invalid safety budget");
    }
    multidex.limits.Validate();
    if (strength.target_analysis_cost_weeks != 0U &&
        !passes.at("strength.analysis_cost_budget").enabled) {
        throw std::invalid_argument(
            "target_analysis_cost_weeks requires strength.analysis_cost_budget");
    }
    if (passes.at("anti_analysis.debug_info_removal").enabled &&
        passes.at("anti_analysis.debug_local_noise").enabled) {
        throw std::invalid_argument(
            "debug_info_removal and debug_local_noise are mutually exclusive");
    }
    for (const auto& descriptor : PassRegistry()) {
        const auto found = passes.find(descriptor.id);
        if (found == passes.end()) throw std::logic_error("pass registry/config mismatch");
        const auto& pass = found->second;
        if (!std::isfinite(pass.intensity) || pass.intensity < 0.0 || pass.intensity > 1.0) {
            throw std::invalid_argument("pass intensity must be in [0,1]: " + std::string(descriptor.id));
        }
        if (pass.enabled && pass.intensity == 0.0) {
            throw std::invalid_argument("enabled pass has zero intensity: " + std::string(descriptor.id));
        }
        if (!descriptor.may_increase_code_size && pass.max_applications_per_method.has_value()) {
            throw std::invalid_argument("application budget is invalid for pass: " + std::string(descriptor.id));
        }
    }
}

} // namespace birch::guard
