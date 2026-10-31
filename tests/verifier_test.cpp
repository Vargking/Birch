#include "birch/dex/builder.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/verifier.h"

#include <algorithm>
#include <cassert>
#include <string>

int main() {
  birch::dex::DexBuilder builder;
  birch::dex::ClassSpec klass;
  klass.descriptor = "Lverify/Test;";
  klass.direct_methods.push_back(
      {"run", "V", {}, 0x0009U, {1U, 0U, 0U, {0x000eU}}});
  builder.AddClass(std::move(klass));
  const auto dex = birch::dex::DexFile::Parse(builder.Build());
  const auto report = birch::dex::VerifyDex(dex);
  assert(report.ok);
  assert(report.classes == 1U);
  assert(report.methods == 1U);
  assert(report.code_items == 1U);
  assert(report.basic_blocks == 1U);

  // A syntactically valid generated <clinit> can still run off its end. Check
  // physical fallthrough, not merely whether the IR has well-formed edges.
  const auto check_flow = [](std::vector<std::uint16_t> units) {
    birch::dex::DexBuilder flow_builder;
    birch::dex::ClassSpec flow_class;
    flow_class.descriptor = "Lverify/Fallthrough;";
    birch::dex::MethodSpec method;
    method.name = "<clinit>";
    method.access_flags = 0x10008U;
    method.body.registers_size = 1U;
    if (units.size() > 2U && units[1U] == 0x0023U)
      method.body.references.push_back({birch::dex::TypeReference{"[B"}, 2U, false});
    method.body.code_units = std::move(units);
    flow_class.direct_methods.push_back(std::move(method));
    flow_builder.AddClass(std::move(flow_class));
    return birch::dex::VerifyDex(birch::dex::DexFile::Parse(flow_builder.Build()),
                                 birch::dex::VerificationLevel::Full);
  };
  assert(check_flow({0x0012U, 0x000eU}).ok);
  assert(check_flow({0x0012U, 0x0038U, 0xffffU, 0x000eU}).ok);
  assert(!check_flow({0x0012U}).ok);
  assert(!check_flow({0x0012U, 0x0038U, 0xffffU}).ok);
  // The fill target is valid, but execution must not continue into the data.
  const auto payload_fallthrough = check_flow({0x1012U, 0x0023U, 0U, 0x0026U, 3U, 0U,
                                               0x0300U, 1U, 1U, 0U, 0U});
  assert(!payload_fallthrough.ok);
  assert(std::any_of(payload_fallthrough.issues.begin(), payload_fallthrough.issues.end(),
      [](const auto& issue) { return issue.message.find("falls off code or into payload") != std::string::npos; }));

  birch::dex::DexBuilder float_builder;
  birch::dex::ClassSpec float_class;
  float_class.descriptor = "Lverify/FloatTypes;";
  birch::dex::MethodSpec valid_float;
  valid_float.name = "valid";
  valid_float.return_type = "I";
  valid_float.access_flags = 0x0009U;
  valid_float.body.registers_size = 3U;
  valid_float.body.code_units = {
      0x0014U, 0x0000U, 0x7fc0U, // const v0, quiet NaN bits
      0x0115U, 0x3f80U,          // const/high16 v1, 1.0f
      0x022dU, 0x0100U,          // cmpl-float v2, v0, v1
      0x020fU,
  };
  float_class.direct_methods.push_back(std::move(valid_float));
  float_builder.AddClass(std::move(float_class));
  assert(
      birch::dex::VerifyDex(birch::dex::DexFile::Parse(float_builder.Build()),
                            birch::dex::VerificationLevel::Full)
          .ok);

  birch::dex::DexBuilder invalid_builder;
  birch::dex::ClassSpec invalid_class;
  invalid_class.descriptor = "Lverify/InvalidFloatTypes;";
  birch::dex::MethodSpec invalid_float;
  invalid_float.name = "invalid";
  invalid_float.return_type = "I";
  invalid_float.access_flags = 0x0009U;
  invalid_float.body.registers_size = 3U;
  invalid_float.body.code_units = {
      0x1012U,          // const/4 v0, #1
      0x0115U, 0x3f80U, // const/high16 v1, 1.0f
      0x00d8U, 0x0100U, // add-int/lit8 v0, v0, #1
      0x022dU, 0x0100U, // invalid: cmpl-float v2, v0, v1
      0x020fU,
  };
  invalid_class.direct_methods.push_back(std::move(invalid_float));
  invalid_builder.AddClass(std::move(invalid_class));
  const auto invalid_report =
      birch::dex::VerifyDex(birch::dex::DexFile::Parse(invalid_builder.Build()),
                            birch::dex::VerificationLevel::Full);
  assert(!invalid_report.ok);
  assert(!invalid_report.issues.empty());

  // ART verifies unreachable executable islands with undefined input
  // registers. A self move after return must therefore be rejected even
  // though normal entry dataflow cannot reach it.
  birch::dex::DexBuilder dead_move_builder;
  birch::dex::ClassSpec dead_move_class;
  dead_move_class.descriptor = "Lverify/DeadMove;";
  birch::dex::MethodSpec dead_move;
  dead_move.name = "invalid";
  dead_move.access_flags = 0x0009U;
  dead_move.body.registers_size = 1U;
  dead_move.body.code_units = {
      0x000eU, // return-void
      0x0003U,
      0U,
      0U, // unreachable move/16 v0, v0
  };
  dead_move_class.direct_methods.push_back(std::move(dead_move));
  dead_move_builder.AddClass(std::move(dead_move_class));
  const auto dead_move_report = birch::dex::VerifyDex(
      birch::dex::DexFile::Parse(dead_move_builder.Build()),
      birch::dex::VerificationLevel::Full);
  assert(!dead_move_report.ok);
  assert(std::any_of(dead_move_report.issues.begin(),
                     dead_move_report.issues.end(), [](const auto &issue) {
                       return issue.message.find("undefined register") !=
                              std::string::npos;
                     }));

  // ART rejects invoke argument words that exceed the code item's outs_size.
  birch::dex::DexBuilder outs_builder;
  birch::dex::ClassSpec outs_class;
  outs_class.descriptor = "Lverify/Outs;";
  birch::dex::MethodSpec sink;
  sink.name = "sink";
  sink.parameter_types = {"I"};
  sink.body.registers_size = 1U;
  sink.body.ins_size = 1U;
  sink.body.code_units = {0x000eU};
  outs_class.direct_methods.push_back(std::move(sink));
  birch::dex::MethodSpec bad_outs;
  bad_outs.name = "bad";
  bad_outs.body.registers_size = 1U;
  bad_outs.body.outs_size = 0U;
  bad_outs.body.code_units = {
      0x1012U,             // const/4 v0, #1
      0x1071U, 0U, 0x0000U, // invoke-static {v0}, sink(I)V
      0x000eU,
  };
  bad_outs.body.references = {
      {birch::dex::MethodReference{"Lverify/Outs;", "sink", "V", {"I"}},
       2U, false},
  };
  outs_class.direct_methods.push_back(std::move(bad_outs));
  outs_builder.AddClass(std::move(outs_class));
  const auto outs_report = birch::dex::VerifyDex(
      birch::dex::DexFile::Parse(outs_builder.Build()),
      birch::dex::VerificationLevel::Full);
  assert(!outs_report.ok);
  assert(std::any_of(outs_report.issues.begin(), outs_report.issues.end(),
                     [](const auto &issue) {
                       return issue.message.find("outs_size") !=
                              std::string::npos;
                     }));

  // A reference/int join is ART Conflict even though if-eqz accepts either
  // category independently.
  birch::dex::DexBuilder conflict_builder;
  birch::dex::ClassSpec conflict_class;
  conflict_class.descriptor = "Lverify/Conflict;";
  birch::dex::MethodSpec conflict_method;
  conflict_method.name = "bad";
  conflict_method.parameter_types = {"Ljava/lang/Object;"};
  conflict_method.body.registers_size = 2U;
  conflict_method.body.ins_size = 1U;
  conflict_method.body.code_units = {
      0x0012U,             // const/4 v0, #0
      0x0038U, 0x0004U,    // if-eqz v0, reference arm
      0x1012U,             // const/4 v0, #1
      0x0228U,             // goto join
      0x1007U,             // move-object v0, v1
      0x0038U, 0x0002U,    // join: if-eqz v0, return
      0x000eU,
  };
  conflict_class.direct_methods.push_back(std::move(conflict_method));
  conflict_builder.AddClass(std::move(conflict_class));
  const auto conflict_report = birch::dex::VerifyDex(
      birch::dex::DexFile::Parse(conflict_builder.Build()),
      birch::dex::VerificationLevel::Full);
  assert(!conflict_report.ok);
  assert(std::any_of(conflict_report.issues.begin(),
                     conflict_report.issues.end(), [](const auto &issue) {
                       return issue.message.find("zero comparison") !=
                              std::string::npos;
                     }));
  // Null must survive move-object and joins without erasing [D. In Kotlin
  // lateinit paths the throw helper has a void return, so both paths remain
  // visible to the verifier even though the null path throws at runtime.
  const auto verify_array_join = [](bool use_long) {
    birch::dex::DexBuilder array_builder;
    birch::dex::ClassSpec array_class;
    array_class.descriptor = "Lverify/ArrayJoin;";
    birch::dex::MethodSpec array_method;
    array_method.name = "store";
    array_method.parameter_types = {"[D", "D", "I"};
    array_method.body.registers_size = 7U;
    array_method.body.ins_size = 4U;
    array_method.body.code_units = {
        0x0012U,             // const/4 v0, #0 (null)
        0x0038U, 0x0004U,    // if-eqz v0, null arm@5
        0x3007U,             // move-object v0, v3 ([D)
        0x0228U,             // goto join@6
        0x0007U,             // move-object v0, v0 (null stays null)
        0x0145U, 0x0600U,    // aget-wide v1, v0, v6
        0x01abU, 0x0401U,    // add-double v1, v1, v4
        0x014cU, 0x0600U,    // aput-wide v1, v0, v6
        0x000eU,
    };
    if (use_long) {
      array_method.body.code_units[8U] = 0x019bU; // add-long (invalid [D value)
      array_method.parameter_types[1U] = "J";
    }
    array_class.direct_methods.push_back(std::move(array_method));
    array_builder.AddClass(std::move(array_class));
    return birch::dex::VerifyDex(
        birch::dex::DexFile::Parse(array_builder.Build()),
        birch::dex::VerificationLevel::Full);
  };
  assert(verify_array_join(false).ok);
  assert(!verify_array_join(true).ok);
  return 0;
}
