if(NOT DEFINED BIRCH_EXECUTABLE OR NOT DEFINED BIRCH_INPUT_GENERATOR OR
   NOT DEFINED BIRCH_TEST_DIR)
    message(FATAL_ERROR "Diagnostic CLI test requires executable/generator/test paths")
endif()

file(MAKE_DIRECTORY "${BIRCH_TEST_DIR}")
file(WRITE "${BIRCH_TEST_DIR}/invalid.dex" "not a DEX file")
execute_process(COMMAND "${BIRCH_INPUT_GENERATOR}" "${BIRCH_TEST_DIR}"
    RESULT_VARIABLE generated OUTPUT_VARIABLE generated_output ERROR_VARIABLE generated_error)
if(NOT "${generated}" STREQUAL "0")
    message(FATAL_ERROR "Cannot generate CLI inputs: ${generated_output}${generated_error}")
endif()

function(check_cli label expected_code expected_text)
    execute_process(COMMAND "${BIRCH_EXECUTABLE}" ${ARGN}
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error
        TIMEOUT 30)
    if(NOT "${result}" STREQUAL "${expected_code}")
        message(FATAL_ERROR "${label}: expected exit ${expected_code}, got ${result}\n${output}${error}")
    endif()
    if(NOT "${output}${error}" MATCHES "${expected_text}")
        message(FATAL_ERROR "${label}: expected diagnostic '${expected_text}'\n${output}${error}")
    endif()
endfunction()

check_cli(help 0 "usage: Birch" --help)
check_cli(short_help 0 "usage: Birch" -h)
check_cli(no_arguments 2 "usage: Birch")
check_cli(help_extra 2 "usage: Birch" --help extra)
check_cli(missing_partition 2 "usage: Birch" --partition)
check_cli(missing_apk 2 "usage: Birch" --inspect-apk)
check_cli(unknown_command 2 "unknown option" --unknown)
check_cli(unknown_dex_option 2 "unknown DEX option"
    "${BIRCH_TEST_DIR}/classes.dex" --unknown)
check_cli(unknown_before_io 2 "unknown DEX option"
    "${BIRCH_TEST_DIR}/missing.dex" --unknown)
check_cli(excess_arguments 2 "usage: Birch" one two three)
check_cli(missing_file 1 "cannot open input" "${BIRCH_TEST_DIR}/missing.dex")
check_cli(invalid_file 1 "invalid DEX" "${BIRCH_TEST_DIR}/invalid.dex" --verify)
check_cli(invalid_apk 1 "Birch:" --inspect-apk "${BIRCH_TEST_DIR}/invalid.dex")
check_cli(missing_directory 1 "Birch:" --partition "${BIRCH_TEST_DIR}/missing-directory")
check_cli(inspect_dex 0 "DEX version:" "${BIRCH_TEST_DIR}/classes.dex")
check_cli(map_dex 0 "type=0x" "${BIRCH_TEST_DIR}/classes.dex" --map)
check_cli(verify_dex 0 "full-verifier: ok" "${BIRCH_TEST_DIR}/classes.dex" --verify)
check_cli(scan_dex 0 "basic blocks:" "${BIRCH_TEST_DIR}/classes.dex" --scan-cfg)
check_cli(audit_unprotected_dex 1 "missing entry dispatcher:"
    "${BIRCH_TEST_DIR}/classes.dex" --audit-cff)
check_cli(inspect_apk 0 "DEX files: 1" --inspect-apk "${BIRCH_TEST_DIR}/input.apk")
message(STATUS "Diagnostic CLI: 20 process/exit/diagnostic cases passed")
