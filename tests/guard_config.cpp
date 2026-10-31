#include "birch/guard/config.h"
#include "birch/io/file.h"

#include <cassert>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>

int main() {
    const auto defaults = birch::guard::GuardConfig::Defaults();
    defaults.Validate();
    const auto config_directory = std::filesystem::path(BIRCH_TEST_SOURCE_DIR) / "configs";
    for (const auto name : {"rename_only.json", "resource_only.json", "release_full.json"}) {
        const auto config = birch::guard::GuardConfig::Parse(
            birch::io::ReadTextFile(config_directory / name));
        config.Validate();
        assert(config.android_dex.empty());
        assert(config.scope.protect.front().pattern == "Lcom/example/**;");
    }
    const auto parsed = birch::guard::GuardConfig::Parse(R"json({
      "schema_version": 1,
      "seed": 42,
      "scope": {"protect": [{"pattern": "Lcom/example/**;"}], "keep": []},
      "passes": {
        "cfg.flattening": {"enabled": true, "intensity": 0.8, "seed": 7},
        "fake.classes": {"enabled": true, "intensity": 0.4, "max_applications_per_method": 3}
      },
      "multidex": {"repartition": true, "limits": {"methods": 64000}}
    })json");
    assert(parsed.seed == 42U);
    assert(parsed.passes.at("cfg.flattening").enabled);
    assert(parsed.passes.at("cfg.flattening").intensity == 0.8);
    assert(parsed.multidex.repartition);
    bool rejected = false;
    try {
        (void)birch::guard::GuardConfig::Parse(R"json({"unexpected": true})json");
    } catch (const std::exception&) {
        rejected = true;
    }
    assert(rejected);
    bool rejected_resource_dictionary = false;
    try {
        (void)birch::guard::GuardConfig::Parse(R"json({
          "resources": {"rename_names": true, "dictionary": "a-1"}
        })json");
    } catch (const std::invalid_argument&) {
        rejected_resource_dictionary = true;
    }
    assert(rejected_resource_dictionary);
    for (const auto& invalid : {std::string("\xe0\x81\xa1"),
                               std::string("\xc0\xaf"),
                               std::string("\xed\xa0\x80"),
                               std::string("\xf0\x9f\x98\x80"),
                               std::string("\xe4\xb8"),
                               std::string("/")}) {
        auto bad_dictionary = defaults;
        bad_dictionary.rename.dictionary = invalid;
        bool rejected_dictionary = false;
        try { bad_dictionary.Validate(); }
        catch (const std::invalid_argument&) { rejected_dictionary = true; }
        assert(rejected_dictionary);
    }
    auto unicode_dictionary = defaults;
    unicode_dictionary.rename.dictionary = "\xe4\xb8\xad\xe6\x96\x87";
    unicode_dictionary.Validate();
    const auto resource_config = birch::guard::GuardConfig::Parse(R"json({
      "resources": {"rename_names": true, "dictionary": "a_19"}
    })json");
    assert(resource_config.resources.dictionary == "a_19");
    auto randomized = defaults;
    randomized.strength.randomized_parameters = true;
    randomized.passes.at("strength.build_parameter_randomization").enabled = true;
    randomized.strength.reproducible_output = true;
    assert(birch::guard::StrengthRandomizedSeed(randomized) ==
           birch::guard::StrengthRandomizedSeed(randomized));
    randomized.strength.reproducible_output = false;
    const auto first_seed = birch::guard::StrengthRandomizedSeed(randomized);
    const auto second_seed = birch::guard::StrengthRandomizedSeed(randomized);
    assert(first_seed != second_seed);
    const auto replay = birch::guard::GuardConfig::Parse(R"json({
      "seed": "18446744073709551615", "effective_seed": "16919314818285478265",
      "passes": {"cfg.flattening": {"seed": "9007199254740993"}}
    })json");
    assert(replay.seed == UINT64_MAX);
    assert(birch::guard::StrengthRandomizedSeed(replay) == 16919314818285478265ULL);
    assert(replay.passes.at("cfg.flattening").seed == 9007199254740993ULL);
    for (const auto bad : {
        R"({"seed":18446744073709551616})", R"({"seed":9007199254740993})",
        R"({"effective_seed":"18446744073709551616"})", R"({"effective_seed":"-1"})",
        R"({"effective_seed":"17x"})", R"({"effective_seed":""})",
        R"({"schema_version":4294967297})", R"({"fake":{"class_count":4294967297}})",
        R"({"budget":{"max_code_units_per_method":4295032296}})",
        R"({"multidex":{"limits":{"methods":4295031296}}})"}) {
        bool failed = false;
        try { (void)birch::guard::GuardConfig::Parse(bad); }
        catch (const std::invalid_argument&) { failed = true; }
        assert(failed);
    }
    for (const auto invalid : {std::numeric_limits<double>::infinity(),
                               std::numeric_limits<double>::quiet_NaN()}) {
        for (unsigned field = 0; field < 3U; ++field) {
            auto config = defaults;
            if (field == 0U) config.budget.max_method_growth_ratio = invalid;
            if (field == 1U) config.budget.max_dex_growth_ratio = invalid;
            if (field == 2U) config.passes.at("cfg.flattening").intensity = invalid;
            bool failed = false;
            try { config.Validate(); }
            catch (const std::invalid_argument&) { failed = true; }
            assert(failed);
        }
    }
    return 0;
}
