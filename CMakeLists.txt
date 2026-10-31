cmake_minimum_required(VERSION 3.22)
project(Birch LANGUAGES CXX)
if(MSVC)
    add_compile_options(/utf-8)
endif()

include(GNUInstallDirs)

option(BIRCH_BUILD_TESTS "Build BirchDex tests" ON)
option(BIRCH_BUILD_GUI "Build Dear ImGui desktop studio (OpenGL 3)" ON)

find_package(ZLIB QUIET)
if (NOT ZLIB_FOUND)
    get_filename_component(BIRCH_MINGW_ROOT "${CMAKE_CXX_COMPILER}" DIRECTORY)
    get_filename_component(BIRCH_MINGW_ROOT "${BIRCH_MINGW_ROOT}" DIRECTORY)
    set(ZLIB_INCLUDE_DIR "${BIRCH_MINGW_ROOT}/include")
    set(ZLIB_LIBRARY "${BIRCH_MINGW_ROOT}/lib/libz.a")
    if(NOT EXISTS "${ZLIB_INCLUDE_DIR}/zlib.h" OR NOT EXISTS "${ZLIB_LIBRARY}")
        message(FATAL_ERROR "zlib development files not found. Install zlib and set ZLIB_ROOT or ZLIB_INCLUDE_DIR/ZLIB_LIBRARY.")
    endif()
    add_library(BirchZlib UNKNOWN IMPORTED)
    set_target_properties(BirchZlib PROPERTIES IMPORTED_LOCATION "${ZLIB_LIBRARY}" INTERFACE_INCLUDE_DIRECTORIES "${ZLIB_INCLUDE_DIR}")
    set(BIRCH_ZLIB_TARGET BirchZlib)
else()
    set(BIRCH_ZLIB_TARGET ZLIB::ZLIB)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(BirchDex STATIC
    src/birch/dex/cfg.cpp
    src/birch/dex/checksum.cpp
    src/birch/dex/cloner.cpp
    src/birch/dex/builder.cpp
    src/birch/dex/code.cpp
    src/birch/dex/dex_file.cpp
    src/birch/dex/ir.cpp
    src/birch/dex/liveness.cpp
    src/birch/dex/leb128.cpp
    src/birch/dex/linker.cpp
    src/birch/dex/linkage_verifier.cpp
    src/birch/dex/inheritance_verifier.cpp
    src/birch/dex/partition.cpp
    src/birch/dex/program.cpp
    src/birch/dex/remap.cpp
    src/birch/dex/region_exception_contract.cpp
    src/birch/dex/monitor_depth.cpp
    src/birch/dex/region_replacement.cpp
    src/birch/dex/type_analysis.cpp
    src/birch/dex/verifier.cpp
)

target_include_directories(BirchDex
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(BirchDex PUBLIC cxx_std_20)

add_library(BirchGuardLib STATIC
    src/birch/io/file.cpp
    src/birch/io/apk_entries.cpp
    src/birch/utils/hash.cpp
    src/birch/utils/wildcard.cpp
    src/birch/guard/scope.cpp
    src/birch/guard/config.cpp
    src/birch/guard/dex_lowering.cpp
    src/birch/guard/constant_program_outliner.cpp
    src/birch/guard/linear_region_outliner.cpp
    src/birch/guard/cfg_region_planner.cpp
    src/birch/guard/cfg_region_outliner.cpp
    src/birch/guard/prefix_assembler.cpp
    src/birch/guard/cff_assembler.cpp
    src/birch/guard/cff_code_budget.cpp
    src/birch/guard/cff_partition_planner.cpp
    src/birch/guard/cff_switch_emitter.cpp
    src/birch/guard/cff_type_domains.cpp
    src/birch/guard/cff_transition_encoder.cpp
    src/birch/guard/cff_joint_token.cpp
    src/birch/guard/dead_state_emitter.cpp
    src/birch/guard/dead_state_router.cpp
    src/birch/guard/control_flow_flattener.cpp
    src/birch/guard/strength_policy.cpp
    src/birch/guard/model_lowering.cpp
    src/birch/guard/model_support.cpp
    src/birch/guard/class_namespace.cpp
    src/birch/guard/model_classes.cpp
    src/birch/guard/model_methods.cpp
    src/birch/guard/model_arrays.cpp
    src/birch/guard/model_enums.cpp
    src/birch/guard/model_runtime.cpp
    src/birch/guard/model_strings.cpp
    src/birch/guard/static_field_initializer.cpp
    src/birch/guard/model_reflection.cpp
    src/birch/guard/model_metadata.cpp
    src/birch/guard/string_runtime.cpp
    src/birch/guard/apk.cpp
    src/birch/guard/apk_dex_layout.cpp
    src/birch/guard/axml.cpp
    src/birch/guard/arsc.cpp
    src/birch/guard/resource_obfuscator.cpp
    src/birch/guard/technique_report.cpp
    src/birch/guard/technique_catalog.cpp
    src/birch/guard/json.cpp
    src/birch/guard/pipeline.cpp
    src/birch/guard/output_linkage.cpp
    src/birch/guard/output_code_budget.cpp
    src/birch/guard/package_access.cpp
    src/birch/guard/method_conflicts.cpp
    src/birch/guard/rename_names.cpp
    src/birch/guard/runtime_contract.cpp
    src/birch/guard/rename_planner.cpp
    src/birch/guard/pass.cpp
    src/birch/guard/zip.cpp
    src/birch/guard/opaque.cpp
    src/birch/guard/control_flow.cpp
    src/birch/guard/fake.cpp
)

target_include_directories(BirchGuardLib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(BirchGuardLib PUBLIC cxx_std_20)
target_link_libraries(BirchGuardLib PUBLIC BirchDex ${BIRCH_ZLIB_TARGET})

if (MSVC)
    target_compile_options(BirchDex PRIVATE /W4 /permissive-)
    target_compile_options(BirchGuardLib PRIVATE /W4 /permissive-)
else()
    target_compile_options(BirchDex PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    target_compile_options(BirchGuardLib PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

add_executable(Birch main.cpp tools/diagnostic_options.cpp)
target_link_libraries(Birch PRIVATE BirchGuardLib)
if(MSVC)
    target_compile_options(Birch PRIVATE /W4 /permissive-)
else()
    target_compile_options(Birch PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

add_executable(BirchGuard tools/birch_guard_main.cpp)
target_link_libraries(BirchGuard PRIVATE BirchGuardLib)

add_executable(BirchLinkageAudit tools/linkage_audit_main.cpp)
target_link_libraries(BirchLinkageAudit PRIVATE BirchGuardLib)

if(BIRCH_BUILD_GUI)
    add_subdirectory(tools/gui)
endif()

if (BIRCH_BUILD_TESTS)
    enable_testing()
    add_executable(BirchCliTestInputs tests/support/generate_cli_inputs.cpp)
    target_link_libraries(BirchCliTestInputs PRIVATE BirchGuardLib)
    add_test(NAME BirchDiagnosticCliTest COMMAND ${CMAKE_COMMAND}
        -DBIRCH_EXECUTABLE=$<TARGET_FILE:Birch>
        -DBIRCH_INPUT_GENERATOR=$<TARGET_FILE:BirchCliTestInputs>
        -DBIRCH_TEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/diagnostic-cli-test
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/diagnostic_cli_test.cmake)
    set_tests_properties(BirchDiagnosticCliTest PROPERTIES TIMEOUT 120)
    add_executable(BirchTechniqueReportTest tests/technique_report_test.cpp)
    target_include_directories(BirchTechniqueReportTest PRIVATE src/birch/guard)
    target_link_libraries(BirchTechniqueReportTest PRIVATE BirchGuardLib)
    add_test(NAME BirchTechniqueReportTest COMMAND BirchTechniqueReportTest)
    add_executable(BirchDexSmokeTest tests/dex_smoke.cpp)
    target_link_libraries(BirchDexSmokeTest PRIVATE BirchDex)
    add_test(NAME BirchDexSmokeTest COMMAND BirchDexSmokeTest)

    add_executable(BirchGuardConfigTest tests/guard_config.cpp)
    target_link_libraries(BirchGuardConfigTest PRIVATE BirchGuardLib)
    add_test(NAME BirchGuardConfigTest COMMAND BirchGuardConfigTest)

    add_executable(BirchZipTest tests/zip_test.cpp)
    target_link_libraries(BirchZipTest PRIVATE BirchGuardLib)
    add_test(NAME BirchZipTest COMMAND BirchZipTest)

    add_executable(BirchApkTest tests/apk_test.cpp)
    target_link_libraries(BirchApkTest PRIVATE BirchGuardLib)
    add_test(NAME BirchApkTest COMMAND BirchApkTest)

    add_executable(BirchApkDexLayoutTest tests/apk_dex_layout_test.cpp)
    target_link_libraries(BirchApkDexLayoutTest PRIVATE BirchGuardLib)
    add_test(NAME BirchApkDexLayoutTest COMMAND BirchApkDexLayoutTest)

    add_executable(BirchOpaqueTest tests/opaque_test.cpp)
    target_link_libraries(BirchOpaqueTest PRIVATE BirchGuardLib)
    add_test(NAME BirchOpaqueTest COMMAND BirchOpaqueTest)

    add_executable(BirchControlFlowTest tests/control_flow_test.cpp)
    target_link_libraries(BirchControlFlowTest PRIVATE BirchGuardLib)
    add_test(NAME BirchControlFlowTest COMMAND BirchControlFlowTest)

    add_executable(BirchBuilderTest tests/builder_test.cpp)
    target_link_libraries(BirchBuilderTest PRIVATE BirchDex)
    add_test(NAME BirchBuilderTest COMMAND BirchBuilderTest)

    add_executable(BirchClonerTest tests/cloner_test.cpp)
    target_link_libraries(BirchClonerTest PRIVATE BirchDex)
    add_test(NAME BirchClonerTest COMMAND BirchClonerTest)

    add_executable(BirchFakeTest tests/fake_test.cpp)
    target_link_libraries(BirchFakeTest PRIVATE BirchGuardLib)
    add_test(NAME BirchFakeTest COMMAND BirchFakeTest)

    add_executable(BirchDebugStripTest tests/debug_strip_test.cpp)
    target_link_libraries(BirchDebugStripTest PRIVATE BirchGuardLib)
    add_test(NAME BirchDebugStripTest COMMAND BirchDebugStripTest)

    add_executable(BirchRemapTest tests/remap_test.cpp)
    target_link_libraries(BirchRemapTest PRIVATE BirchDex)
    add_test(NAME BirchRemapTest COMMAND BirchRemapTest)

    add_executable(BirchVerifierTest tests/verifier_test.cpp)
    target_link_libraries(BirchVerifierTest PRIVATE BirchDex)
    add_test(NAME BirchVerifierTest COMMAND BirchVerifierTest)

    add_executable(BirchDexPipelineTest tests/dex_pipeline_test.cpp)
    target_link_libraries(BirchDexPipelineTest PRIVATE BirchGuardLib)
    add_test(NAME BirchDexPipelineTest COMMAND BirchDexPipelineTest)

    add_executable(BirchRuntimeKeepTest tests/runtime_keep_test.cpp)
    target_link_libraries(BirchRuntimeKeepTest PRIVATE BirchGuardLib)
    add_test(NAME BirchRuntimeKeepTest COMMAND BirchRuntimeKeepTest)

    add_executable(BirchLinkerTest tests/linker_test.cpp)
    target_link_libraries(BirchLinkerTest PRIVATE BirchGuardLib)
    add_test(NAME BirchLinkerTest COMMAND BirchLinkerTest)

    add_executable(BirchRenameAccessTest tests/rename_access_test.cpp)
    target_link_libraries(BirchRenameAccessTest PRIVATE BirchGuardLib)
    add_test(NAME BirchRenameAccessTest COMMAND BirchRenameAccessTest)

    add_executable(BirchRenameHierarchyTest tests/rename_hierarchy_test.cpp)
    target_link_libraries(BirchRenameHierarchyTest PRIVATE BirchGuardLib)
    add_test(NAME BirchRenameHierarchyTest COMMAND BirchRenameHierarchyTest)

    add_executable(BirchDexLoweringTest tests/dex_lowering_test.cpp
        tests/support/int_dex_interpreter.cpp)
    target_link_libraries(BirchDexLoweringTest PRIVATE BirchGuardLib)
    add_test(NAME BirchDexLoweringTest COMMAND BirchDexLoweringTest)

    add_executable(BirchModelLoweringTest tests/model_lowering_test.cpp)
    target_link_libraries(BirchModelLoweringTest PRIVATE BirchGuardLib)
    add_test(NAME BirchModelLoweringTest COMMAND BirchModelLoweringTest)

    add_executable(BirchModelPassesExtraTest tests/model_passes_extra_test.cpp)
    target_link_libraries(BirchModelPassesExtraTest PRIVATE BirchGuardLib)
    add_test(NAME BirchModelPassesExtraTest COMMAND BirchModelPassesExtraTest)

    add_executable(BirchStrengthRandomizationTest tests/strength_randomization_test.cpp)
    target_link_libraries(BirchStrengthRandomizationTest PRIVATE BirchGuardLib)
    add_test(NAME BirchStrengthRandomizationTest COMMAND BirchStrengthRandomizationTest)

    add_executable(BirchCfgMaxStrengthTest tests/cfg_max_strength_test.cpp)
    target_link_libraries(BirchCfgMaxStrengthTest PRIVATE BirchGuardLib)
    add_test(NAME BirchCfgMaxStrengthTest COMMAND BirchCfgMaxStrengthTest)

    add_executable(BirchCffSemanticsTest tests/cff_semantics_test.cpp
        tests/support/int_dex_interpreter.cpp
        tests/support/string_dex_interpreter.cpp
        tests/support/string_dex_runtime.cpp)
    target_link_libraries(BirchCffSemanticsTest PRIVATE BirchGuardLib)
    add_test(NAME BirchCffSemanticsTest COMMAND BirchCffSemanticsTest)

    add_executable(BirchCffEncodingTest tests/cff_encoding_test.cpp
        tests/support/int_dex_interpreter.cpp)
    target_include_directories(BirchCffEncodingTest PRIVATE src/birch/guard)
    target_link_libraries(BirchCffEncodingTest PRIVATE BirchGuardLib)
    add_test(NAME BirchCffEncodingTest COMMAND BirchCffEncodingTest)

    add_executable(BirchDeadStateRouterTest tests/dead_state_router_test.cpp
        tests/support/int_dex_interpreter.cpp)
    target_include_directories(BirchDeadStateRouterTest PRIVATE src/birch/guard)
    target_link_libraries(BirchDeadStateRouterTest PRIVATE BirchGuardLib)
    add_test(NAME BirchDeadStateRouterTest COMMAND BirchDeadStateRouterTest)

    add_executable(BirchStaticInitializerTest tests/static_initializer_test.cpp
        tests/support/string_dex_interpreter.cpp tests/support/string_dex_runtime.cpp)
    target_link_libraries(BirchStaticInitializerTest PRIVATE BirchGuardLib)
    add_test(NAME BirchStaticInitializerTest COMMAND BirchStaticInitializerTest)

    add_executable(BirchModelDataCompositionTest tests/model_data_composition_test.cpp
        tests/support/string_dex_interpreter.cpp tests/support/string_dex_runtime.cpp)
    target_include_directories(BirchModelDataCompositionTest PRIVATE src/birch/guard)
    target_link_libraries(BirchModelDataCompositionTest PRIVATE BirchGuardLib)
    add_test(NAME BirchModelDataCompositionTest COMMAND BirchModelDataCompositionTest)

    add_executable(BirchStaticInitializerChunkTest tests/static_initializer_chunk_test.cpp
        tests/support/string_dex_interpreter.cpp tests/support/string_dex_runtime.cpp)
    target_link_libraries(BirchStaticInitializerChunkTest PRIVATE BirchGuardLib)
    add_test(NAME BirchStaticInitializerChunkTest COMMAND BirchStaticInitializerChunkTest)

    add_executable(BirchSyntheticNamespaceTest tests/synthetic_namespace_test.cpp)
    target_include_directories(BirchSyntheticNamespaceTest PRIVATE src/birch/guard)
    target_link_libraries(BirchSyntheticNamespaceTest PRIVATE BirchGuardLib)
    add_test(NAME BirchSyntheticNamespaceTest COMMAND BirchSyntheticNamespaceTest)

    add_executable(BirchLoweringProbe tools/lowering_probe.cpp)
    target_link_libraries(BirchLoweringProbe PRIVATE BirchGuardLib)

    add_executable(BirchPolymorphicZeroBranchTest tests/polymorphic_zero_branch_test.cpp
        tests/support/string_dex_interpreter.cpp tests/support/string_dex_runtime.cpp)
    target_link_libraries(BirchPolymorphicZeroBranchTest PRIVATE BirchGuardLib)
    add_test(NAME BirchPolymorphicZeroBranchTest COMMAND BirchPolymorphicZeroBranchTest)

    add_executable(BirchConstantMergeTest tests/constant_merge_test.cpp
        tests/support/string_dex_interpreter.cpp tests/support/string_dex_runtime.cpp)
    target_link_libraries(BirchConstantMergeTest PRIVATE BirchGuardLib)
    add_test(NAME BirchConstantMergeTest COMMAND BirchConstantMergeTest)

    add_executable(BirchCffTypeDomainsTest tests/cff_type_domains_test.cpp)
    target_include_directories(BirchCffTypeDomainsTest PRIVATE src/birch/guard)
    target_link_libraries(BirchCffTypeDomainsTest PRIVATE BirchGuardLib)
    add_test(NAME BirchCffTypeDomainsTest COMMAND BirchCffTypeDomainsTest)

    add_executable(BirchLivenessTest tests/liveness_test.cpp)
    target_link_libraries(BirchLivenessTest PRIVATE BirchDex)
    add_test(NAME BirchLivenessTest COMMAND BirchLivenessTest)

    add_executable(BirchResourcePlanTest tests/resource_plan_test.cpp)
    target_include_directories(BirchResourcePlanTest PRIVATE src/birch/guard)
    target_link_libraries(BirchResourcePlanTest PRIVATE BirchGuardLib)
    add_test(NAME BirchResourcePlanTest COMMAND BirchResourcePlanTest)

    add_executable(BirchCffTransitionEncoderTest tests/cff_transition_encoder_test.cpp
        tests/support/int_dex_interpreter.cpp)
    target_include_directories(BirchCffTransitionEncoderTest PRIVATE src/birch/guard)
    target_link_libraries(BirchCffTransitionEncoderTest PRIVATE BirchGuardLib)
    add_test(NAME BirchCffTransitionEncoderTest COMMAND BirchCffTransitionEncoderTest)

    add_executable(BirchConstantProgramOutlinerTest tests/constant_program_outliner_test.cpp
        tests/support/string_dex_interpreter.cpp tests/support/string_dex_runtime.cpp)
    target_include_directories(BirchConstantProgramOutlinerTest PRIVATE src/birch/guard)
    target_link_libraries(BirchConstantProgramOutlinerTest PRIVATE BirchGuardLib)
    add_test(NAME BirchConstantProgramOutlinerTest COMMAND BirchConstantProgramOutlinerTest)

    add_executable(BirchLinearRegionOutlinerTest tests/linear_region_outliner_test.cpp
        tests/support/string_dex_interpreter.cpp tests/support/string_dex_runtime.cpp)
    target_include_directories(BirchLinearRegionOutlinerTest PRIVATE src/birch/guard)
    target_link_libraries(BirchLinearRegionOutlinerTest PRIVATE BirchGuardLib)
    add_test(NAME BirchLinearRegionOutlinerTest COMMAND BirchLinearRegionOutlinerTest)
    set_tests_properties(BirchLinearRegionOutlinerTest PROPERTIES TIMEOUT 1200 RUN_SERIAL TRUE)

    add_executable(BirchCfgRegionOutlinerTest tests/cfg_region_outliner_test.cpp
        tests/support/string_dex_interpreter.cpp tests/support/string_dex_runtime.cpp)
    target_include_directories(BirchCfgRegionOutlinerTest PRIVATE src/birch/guard)
    target_link_libraries(BirchCfgRegionOutlinerTest PRIVATE BirchGuardLib)
    add_test(NAME BirchCfgRegionOutlinerTest COMMAND BirchCfgRegionOutlinerTest)
    set_tests_properties(BirchCfgRegionOutlinerTest PROPERTIES TIMEOUT 1200 RUN_SERIAL TRUE)

    add_executable(BirchCffPartitionPlannerTest tests/cff_partition_planner_test.cpp
        tests/support/string_dex_interpreter.cpp tests/support/string_dex_runtime.cpp)
    target_include_directories(BirchCffPartitionPlannerTest PRIVATE src/birch/guard)
    target_link_libraries(BirchCffPartitionPlannerTest PRIVATE BirchGuardLib)
    add_test(NAME BirchCffPartitionPlannerTest COMMAND BirchCffPartitionPlannerTest)

    add_executable(BirchCfgExceptionRegionsTest tests/cfg_exception_regions_test.cpp
        tests/support/string_dex_interpreter.cpp tests/support/string_dex_runtime.cpp)
    target_include_directories(BirchCfgExceptionRegionsTest PRIVATE src/birch/guard)
    target_link_libraries(BirchCfgExceptionRegionsTest PRIVATE BirchGuardLib)
    add_test(NAME BirchCfgExceptionRegionsTest COMMAND BirchCfgExceptionRegionsTest)

    add_executable(BirchOutputCodeBudgetTest tests/output_code_budget_test.cpp
        tests/support/string_dex_interpreter.cpp tests/support/string_dex_runtime.cpp)
    target_include_directories(BirchOutputCodeBudgetTest PRIVATE src/birch/guard)
    target_link_libraries(BirchOutputCodeBudgetTest PRIVATE BirchGuardLib)
    add_test(NAME BirchOutputCodeBudgetTest COMMAND BirchOutputCodeBudgetTest)

    # Self-contained synthetic regressions; no application APK/DEX fixtures.
    set_tests_properties(BirchCffEncodingTest BirchCffTypeDomainsTest
        BirchLivenessTest BirchCfgRegionOutlinerTest BirchCffPartitionPlannerTest
        BirchCfgExceptionRegionsTest BirchOutputCodeBudgetTest PROPERTIES LABELS "cff-budget")
    set_tests_properties(BirchLinearRegionOutlinerTest PROPERTIES LABELS "extended")

    set(BIRCH_TEST_TARGETS
        BirchTechniqueReportTest BirchCfgRegionOutlinerTest BirchCffPartitionPlannerTest BirchCfgExceptionRegionsTest BirchOutputCodeBudgetTest
        BirchDexSmokeTest BirchGuardConfigTest BirchZipTest BirchApkTest BirchApkDexLayoutTest
        BirchOpaqueTest BirchControlFlowTest BirchBuilderTest BirchClonerTest BirchLivenessTest
        BirchFakeTest BirchResourcePlanTest BirchDebugStripTest
        BirchRemapTest BirchVerifierTest BirchDexPipelineTest
        BirchRuntimeKeepTest BirchLinkerTest BirchRenameAccessTest BirchRenameHierarchyTest BirchDexLoweringTest
        BirchModelLoweringTest BirchModelPassesExtraTest
        BirchStrengthRandomizationTest BirchCfgMaxStrengthTest BirchCffSemanticsTest
        BirchCffEncodingTest BirchDeadStateRouterTest BirchStaticInitializerTest BirchModelDataCompositionTest BirchStaticInitializerChunkTest BirchSyntheticNamespaceTest BirchPolymorphicZeroBranchTest BirchConstantMergeTest BirchCffTypeDomainsTest BirchCffTransitionEncoderTest BirchConstantProgramOutlinerTest BirchLinearRegionOutlinerTest)
    if(BIRCH_BUILD_GUI)
        add_executable(BirchGuiModelTest tests/gui_model_test.cpp)
        target_link_libraries(BirchGuiModelTest PRIVATE BirchGuiModel)
        add_test(NAME BirchGuiModelTest COMMAND BirchGuiModelTest)
        list(APPEND BIRCH_TEST_TARGETS BirchGuiModelTest)
    endif()
    foreach(BIRCH_TEST_TARGET IN LISTS BIRCH_TEST_TARGETS)
        target_compile_definitions(${BIRCH_TEST_TARGET} PRIVATE
            BIRCH_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
        if (MSVC)
            target_compile_options(${BIRCH_TEST_TARGET} PRIVATE /UNDEBUG)
        else()
            target_compile_options(${BIRCH_TEST_TARGET} PRIVATE -UNDEBUG)
        endif()
    endforeach()

    if (WIN32)
        get_filename_component(BIRCH_COMPILER_RUNTIME_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
        set_tests_properties(${BIRCH_TEST_TARGETS} BirchDiagnosticCliTest PROPERTIES
            ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${BIRCH_COMPILER_RUNTIME_DIR}"
        )
    endif()
endif()

# Runtime libraries from the compiler/zlib toolchain may still be needed by
# installed executables. CPack does not bundle them automatically.
install(TARGETS Birch BirchGuard BirchLinkageAudit BirchDex BirchGuardLib
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DATADIR}/birch)
install(DIRECTORY configs/ DESTINATION ${CMAKE_INSTALL_DATADIR}/birch/configs)
install(DIRECTORY licenses/ DESTINATION ${CMAKE_INSTALL_DATADIR}/birch/licenses)
install(FILES ImGUI/imgui-1.93.0/LICENSE.txt DESTINATION ${CMAKE_INSTALL_DATADIR}/birch/licenses/imgui)
install(FILES ImGUI/glfw-3.4/LICENSE.md DESTINATION ${CMAKE_INSTALL_DATADIR}/birch/licenses/glfw)

set(CPACK_PACKAGE_NAME "BirchGuard")
set(CPACK_PACKAGE_VENDOR "Birch")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "C++20 DEX/APK obfuscation toolkit with CLI, desktop GUI and static verification")
set(CPACK_PACKAGE_VERSION "1.1.0")
set(CPACK_GENERATOR "ZIP")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY ON)
include(CPack)
