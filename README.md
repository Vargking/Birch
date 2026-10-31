# Birch

[简体中文](README.zh-CN.md) · English

Birch is a C++20 project for editing Android DEX files and applying obfuscation to DEX and APK files. It has two main modules: **BirchDex**, the DEX editing library, and **BirchGuard**, the configuration-driven transformation pipeline built on top of it.

The project works on DEX instructions and APK structures directly. It does not decompile applications to Java or rebuild them through an Android project. APK output is unsigned and must be signed separately.

## Modules

### BirchDex — DEX editing library

BirchDex provides the file model, writer, and analyses needed to build DEX tools. Use it when you need to inspect bytecode, generate classes, replace method bodies, or redistribute classes between DEX files without running the BirchGuard pipeline.

Its CMake target is `BirchDex`, its namespace is `birch::dex`, and its public headers are in [include/birch/dex](include/birch/dex).

- **Parsing and inspection.** `DexFile::Parse` reads headers, ID tables, class definitions, class data, and the map list. It exposes descriptors, method signatures, fields, strings, and original bytes. Parse errors carry an error code and byte offset.
- **Construction and cloning.** `DexBuilder` builds DEX from `ClassSpec`, `MethodSpec`, and `MethodBodySpec`. Method bodies use code units with symbolic reference patches, so callers do not need to predict final method or string IDs. `DexClassCloner` converts existing classes into this construction model, including supported annotations, static values, exception handlers, and debug information.
- **Rewriting and relocation.** String replacement, debug stripping, ID remapping, instruction replacement, and complete method-body replacement have separate entry points. Writers relocate affected data and code addresses, update references, and regenerate checksums. This is what allows an edit to change size rather than requiring a same-length binary patch.
- **Bytecode analysis.** Instruction decoding and `MethodIr` expose basic blocks and control-flow edges. `ControlFlowGraph`, type analysis, `MethodLiveness`, exception-region analysis, and monitor-depth analysis supply the information needed to decide whether a rewrite is valid.
- **Multi-DEX operations.** `DexProgram` represents several DEX inputs. Linking and inheritance checks resolve relationships across them; the partitioner counts the IDs referenced by each class and groups classes under configured limits. `RepartitionProgram` then clones and rebuilds those groups as separate DEX files.
- **Verification.** Structural, instruction, type, checksum, canonical-order, linkage, and inheritance checks cover different failure modes. They are static checks, not an implementation of the Android runtime.

`DexFile` is not a mutable object tree that automatically serializes every edit. Its `Write()` returns the retained bytes, making an untouched parse/write round trip byte-for-byte stable. Rewriting methods and builders return new byte buffers; parse those buffers when continuing with another edit.

Start with [dex_file.h](include/birch/dex/dex_file.h), [builder.h](include/birch/dex/builder.h), [remap.h](include/birch/dex/remap.h), and [cloner.h](include/birch/dex/cloner.h). The library does not depend on BirchGuard, the GUI, or APK configuration.

### BirchGuard — DEX/APK obfuscation pipeline

BirchGuard uses BirchDex to turn a set of bytecode transformations into an application-level workflow. It decides which classes may change, coordinates passes, keeps cross-file references consistent, and checks the result before writing output.

The implementation is the `BirchGuardLib` static library, in namespace `birch::guard`. The executable named `BirchGuard` is its command-line frontend; it is not a second implementation of the engine.

BirchGuard is responsible for:

- **Configuration and scope.** Parsing JSON, validating pass options, selecting classes through descriptor patterns, and applying keep rules. Renaming, member inclusion, and code transformations can be controlled separately.
- **Transformation planning.** Running class/method-level passes, creating helper code, lowering model changes to DEX instructions, and applying control-flow, string, constant, and metadata transformations.
- **Whole-application renaming.** Building one plan for all DEX files, preserving known lookup and access requirements, and updating supported reflection sites, binary XML, and class-list entries.
- **APK and resource handling.** Reading and rebuilding ZIP entries, rewriting supported manifest/resource references, handling DEX layout and optional repartitioning, and removing signatures that no longer match the modified APK.
- **Validation and reporting.** Enforcing growth and method-size budgets, checking final DEX/linkage/layout, and writing name mappings, technique reports, and progress events.

[GuardPipeline](include/birch/guard/pipeline.h) is the public entry point. `FromJson` and `FromConfig` create a pipeline; `InspectApk`, `TransformDex`, and `TransformApk` perform the work. Overloads accept a `ProgressSink` for embedding in another application.

The supplied frontends share these libraries:

| Target | Purpose |
| --- | --- |
| `BirchGuard` | JSON-driven DEX/APK inspection and transformation |
| `BirchGuardGUI` | Desktop frontend using Dear ImGui, GLFW, and OpenGL 3 |
| `Birch` | DEX map, CFG, verification, CFF audit, and partition diagnostics |
| `BirchLinkageAudit` | Read-only APK/DEX linkage audit, with optional framework metadata |

The dependency direction is frontends → `BirchGuardLib` → `BirchDex`. For a bytecode editor, link `BirchDex`; for the configured protection workflow, link `BirchGuardLib`.

## Build

Requirements:

- CMake 3.22 or newer.
- A C++20 compiler and zlib development files.
- Ninja for the commands below.
- For the GUI: a C compiler, threads, and desktop OpenGL development files.

Dear ImGui 1.93.0 and GLFW 3.4 are included under `ImGUI/`. The build does not download missing dependencies.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBIRCH_BUILD_GUI=ON -DBIRCH_BUILD_TESTS=ON
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure -j 3
```

For a CLI-only build, configure a separate directory with `-DBIRCH_BUILD_GUI=OFF`. Tests can be disabled with `-DBIRCH_BUILD_TESTS=OFF`.

Windows builds have been exercised with MinGW-w64/GCC. Keep the compiler runtime DLLs available on `PATH`. With a Visual Studio generator, omit `-G Ninja`, add `--config Release` to the build command, and use `-C Release` for CTest; that toolchain needs independent validation.

If zlib is not found, set `-DZLIB_ROOT=<prefix>`, or provide `ZLIB_INCLUDE_DIR` and the full `ZLIB_LIBRARY` path. The MinGW fallback uses the compiler installation's zlib only when its headers and library exist.

Linux GUI builds need the development packages for the enabled GLFW X11/Wayland backends and OpenGL. Add `-DGLFW_BUILD_WAYLAND=OFF` if Wayland is not needed. Linux and macOS builds still need broader testing.

### Using the libraries in another project

With Birch checked out under `external/Birch`:

```cmake
set(BIRCH_BUILD_GUI OFF CACHE BOOL "")
set(BIRCH_BUILD_TESTS OFF CACHE BOOL "")
add_subdirectory(external/Birch)

target_link_libraries(my_tool PRIVATE BirchDex)
# For the protection pipeline, link BirchGuardLib instead.
```

Public include directories are propagated by the targets. `BirchGuardLib` also links BirchDex and zlib. The top-level build currently discovers zlib even if your application only links BirchDex. Installed `find_package(Birch)` exports and a stable library ABI are not provided yet.

### Install and package

```sh
cmake --install build --prefix install
cpack --config build/CPackConfig.cmake -G ZIP -B dist
```

For multi-configuration generators, add `--config Release` to installation and `-C Release` to CPack. The ZIP contains installed tools, enabled GUI, libraries, headers, configurations, and dependency notices. Compiler and zlib runtime dependencies are not bundled automatically.

## Usage

### Configuration

Three starting configurations are provided:

| File | Intended use |
| --- | --- |
| [rename_only.json](configs/rename_only.json) | Renaming-focused configuration |
| [resource_only.json](configs/resource_only.json) | APK resource transformations |
| [release_full.json](configs/release_full.json) | High-strength profile with substantial code growth |

Before use, replace `Lcom/example/**;` in `scope.protect` with your application's DEX descriptor pattern. Add keep rules for classes whose names or behavior are used externally. `scope.keep` takes precedence over protect rules.

Unlisted passes inherit engine defaults. The `_only` filenames do not disable other passes automatically; explicitly disable unwanted passes when you need a strict selection. Unknown fields and pass IDs are rejected.

`android_dex` optionally supplies Android framework metadata for inheritance and method resolution. Match it to the target Android API. The framework is analyzed, not copied into the output. Paths in JSON are relative to the process working directory, not the configuration file.

### Command line

Run these commands from the repository root. On Windows, executable names have an `.exe` suffix.

```sh
./build/BirchGuard --list-passes
./build/BirchGuard --config configs/rename_only.json --inspect-apk input.apk
./build/BirchGuard --config configs/rename_only.json --transform-apk input.apk output-unsigned.apk
./build/BirchGuard --config my-dex.json --transform-dex input.dex output.dex
```

For standalone DEX output, disable both resource flags (`resources.rename_files`, `resources.rename_names`) and both resource passes (`resources.file_rename`, `resources.name_rename`).

Diagnostic tools:

```sh
./build/Birch input.dex --verify
./build/Birch input.dex --scan-cfg
./build/Birch input.dex --map
./build/Birch input.dex --audit-cff
./build/BirchLinkageAudit input.apk
./build/BirchLinkageAudit input.apk android.dex --verbose
```

The transformation writes the requested APK/DEX, `<output>.techniques.txt`, and an optional mapping file. The report records the effective seed, implementation descriptions, available application counters, and compatibility warnings. A configured pass may have no eligible site; `not instrumented` means no exact counter is available.

Keep mappings and reports separately from the released application. Input, output, mapping, and report paths must be distinct, including hard-link aliases. The CLI can replace existing output files.

Exit codes are 0 for success, 2 for invalid arguments, and 1 for parsing, transformation, or verification failures.

### GUI and APK signing

Run `build/tools/gui/BirchGuardGUI`. It exposes the same engine through file selection/drag-and-drop, configuration import, scope rules, pass filtering, and strength controls. Work runs on a background thread; settings remain locked until the job finishes. Cancellation and resume are not implemented.

APK output is unsigned. Use external Android SDK tools to align, sign, and verify it. No built-in signing backend is available. Changing the signing certificate can affect application updates and integrations; test the signed APK on the intended devices.

## Implementation

### DEX rewriting and final validation

DEX instructions refer to numeric IDs for strings, types, fields, methods, and prototypes. Adding a helper or changing a descriptor can alter ID ordering and instruction widths. Copying a modified string into the original byte range is therefore not a general rewriting strategy.

BirchDex rebuilds or relocates the affected sections and applies the corresponding ID and address maps. Code rewriting must account for branch offsets, switch and array payloads, try ranges, handler addresses, and debug addresses. Canonical remapping restores the required table ordering; checksums are regenerated after the byte layout is settled.

BirchGuard coordinates this across the application: it plans scope and runtime requirements, performs model and instruction transformations, applies shared renames, optionally repartitions DEX, then rebuilds the APK. Final bytes are parsed again and checked for structure, types, method size, cross-DEX linkage, and legacy DEX loading layout.

See [remap.cpp](src/birch/dex/remap.cpp), [builder.cpp](src/birch/dex/builder.cpp), and [pipeline.cpp](src/birch/guard/pipeline.cpp).

### Cross-DEX renaming

Renaming is planned across all input DEX files rather than independently for each file. A reference from `classes2.dex` must resolve to the same renamed definition in `classes.dex`.

The planner collects names that must remain available, builds method-conflict information, and allocates replacements without introducing known lookup conflicts. Framework names are reserved to avoid accidentally turning an unrelated method into an override. Classes may keep their original package while changing their simple name when moving them would break package-private access.

Recognized reflection sites use a precomputed rename plan. Names used by those sites are locked while model transformations add classes and methods; the final plan checks that those mappings remain stable. Supported manifest, resource XML, service-list, and other class-list references join the same name mapping.

This does not resolve arbitrary dynamically constructed names. JNI, serialization, plugins, and application-specific lookup conventions can still require explicit keep rules.

See [rename_planner.cpp](src/birch/guard/rename_planner.cpp), [runtime_contract.cpp](src/birch/guard/runtime_contract.cpp), and [package_access.cpp](src/birch/guard/package_access.cpp).

### Type-aware control-flow flattening

Control-flow flattening replaces eligible direct block transitions with state updates and dispatcher branches. BirchGuard uses encoded state/selector values, keyed dispatcher levels, joint-token checks, and generated runtime barriers. Dead states form a separate graph with encoded edges, local decoders, and sharded switches.

A shared dispatcher also creates new control-flow joins. If one incoming path holds an integer in a register and another holds an object reference there, merging them can make otherwise valid DEX fail type verification.

`CffTypeDomains` therefore groups exits by compatible register-type states. When liveness projection is enabled, a register can be ignored only if the analysis proves it is overwritten before use. Grouping and liveness are refined until the grouping stops changing, so values made relevant by new shared paths are not lost. Uninitialized references and exception-sensitive states impose additional restrictions.

Explicit `monitor-enter`/`monitor-exit` instructions disable domain sharing: equal register types alone do not establish that the same lock is held on each path.

See [control_flow_flattener.cpp](src/birch/guard/control_flow_flattener.cpp), [cff_type_domains.cpp](src/birch/guard/cff_type_domains.cpp), and [cff_transition_encoder.cpp](src/birch/guard/cff_transition_encoder.cpp).

### Method splitting and code budgets

Flattening, constant expansion, and dead graphs can turn a small source method into a large output method. BirchGuard uses several forms of outlining:

- `ConstantProgramOutliner` moves complete generated constant programs into same-owner helpers, preserving their operations and leaving typed runtime barriers at the call site.
- `LinearRegionOutliner` extracts eligible straight-line regions whose live outputs are unchanged.
- `CfgRegionPlanner` and `CfgRegionOutliner` handle single-entry, single-continuation regions with internal branches or loops. Live inputs become typed arguments; supported live outputs are returned or reconstructed.

A region cannot be split through an `invoke`/`move-result` pair, entered from an external edge in its interior, or moved across incompatible exception contexts. Monitor instructions are not extracted. A region inside one unchanged try context can become a call covered by the original handlers; locks stay in the caller. Generated helpers remain subject to subsequent protection and verification.

`CffCodeBudget` counts emitted instructions, transitions, dead-state code, payloads, and alignment before committing the layout, then reconciles that count against the emitted code. Dedicated budget failures can trigger bounded outlining/replanning retries. CFG refinement starts from the pre-materialization source rather than layering another transform over a failed trial.

The supplied full profile requests 1024 dead states. Full-strength methods also have a 16000-code-unit ceiling, or a lower configured limit. One code unit is 16 bits; setting `max_code_units_per_method` to 65000 does not remove the stricter ceiling. Full CFF uses `const-string/jumbo` before layout is fixed to account for possible string-ID growth.

After renaming and repartitioning, `OutputCodeBudget` checks serialized method sizes again, resolving renamed owners back to the original scope. Remaining overflow is an error; this final check does not repartition or reduce the requested strength.

See [cff_code_budget.cpp](src/birch/guard/cff_code_budget.cpp), [cff_partition_planner.cpp](src/birch/guard/cff_partition_planner.cpp), and [output_code_budget.cpp](src/birch/guard/output_code_budget.cpp).

### Strings and constants

String transformations operate on UTF-16 code units decoded from DEX modified UTF-8, rather than treating a Java string as ordinary UTF-8 bytes. This preserves the representation of embedded NUL and surrogate pairs.

For each string, a stable hash of its value and seed selects one of four XOR/add modes and derives three 16-bit keys. The base transform is followed by eight index-dependent rounds:

```text
x = base_transform(unit, index, k1, k2, k3)
for r = 0 .. 7:
    x ^= uint16(index + 17 * r)
    x += uint16(k1 + 0x1357 * r)
    x ^= uint16(k2 ^ (k3 + 0x246d * r))
    x &= 0xffff
```

The transformed units are stored in generated byte-array payloads. Original string loads call generated helper methods, whose instructions apply the inverse rounds, construct a `String` from a `char[]`, and clear temporary arrays. Complete literals are interned to preserve `const-string` identity behavior; private split fragments are not interned.

Constant passes similarly replace supported loads with XOR/add programs and typed barriers. They must distinguish integer zero from a null reference and preserve the operand types expected by later instructions.

These transformations obscure static representation, but the decoder and keys ship with the application. They are not a substitute for keeping secrets outside the APK.

See [model_strings.cpp](src/birch/guard/model_strings.cpp), [dex_lowering.cpp](src/birch/guard/dex_lowering.cpp), and [constant_program_outliner.cpp](src/birch/guard/constant_program_outliner.cpp).

### Resource rewriting

Resource planning runs against the original DEX strings, before string transformations hide literal references. It examines ARSC strings, resource-name/path API references, assets, native-library presence, and overlay metadata.

Eligible resource filenames receive a collision-checked basename made from 16 dictionary tokens. The directory and suffix are retained, including the full `.9.png` suffix. ZIP entry names and ARSC paths are updated together; supported binary XML path references are updated as well. ZIP entry renames preserve entry order, and the result is checked for matching paths in ARSC and the archive.

Resource key-pool names can be replaced with `BirchGuard` when no detected name dependency blocks the change. Resource IDs, type names, and user-facing values are not intentionally rewritten. Dynamic lookup, literal paths, assets, native code, or overlays can cause individual entries or whole categories to remain unchanged. These checks are conservative heuristics, not a complete analysis of native or dynamically loaded code.

See [resource_obfuscator.cpp](src/birch/guard/resource_obfuscator.cpp), [arsc.cpp](src/birch/guard/arsc.cpp), and [axml.cpp](src/birch/guard/axml.cpp).

### Seeds and replay

The effective seed can differ from the configured `seed`. When build-parameter randomization is enabled, selected configuration values and pass settings are mixed into it. Non-reproducible mode also adds runtime entropy.

To replay a reported parameter set, add the recorded seed at the JSON root:

```json
"effective_seed": "16919314818285478265"
```

Keep the original input, configuration, framework, and engine revision. This overrides seed derivation; it is not a guarantee of identical output across different engine versions or environments. Root and per-pass seeds accept decimal `uint64` strings. Values above 9007199254740991 must use strings to avoid JSON numeric precision loss.

## Tests

Regression inputs are constructed in code or generated at runtime. No third-party application APK or framework DEX is required. Synthetic APKs exercise formats and pipeline behavior; they are not installable applications.

```sh
ctest --test-dir build --output-on-failure
ctest --test-dir build -L cff-budget --output-on-failure
ctest --test-dir build -LE extended --output-on-failure -j 3
```

The full suite includes the slower `extended` tests. `cff-budget` selects regressions for code budgets, type domains, liveness, outlining, exceptions, and monitors. Release tests retain assertions. Test interpreters cover only the instruction/API behavior needed by their cases, not all of ART.

## Known limitations

- Static verification does not replace installation, startup, resource, exception-path, and performance testing on Android devices.
- Dynamic reflection, JNI, serialization, plugins, resource-name lookup, and application integrity checks can break after transformation.
- High-strength profiles increase file size, call depth, build time, and runtime work. Some inputs are rejected by safety or size checks.
- AAB/JAR conversion, native-code protection, a general bytecode VM, and built-in APK signing are not provided. Pass names such as `crypto` or `array_virtualization` describe specific implementations, not those broader capabilities; see [technique_catalog.cpp](src/birch/guard/technique_catalog.cpp).
- Windows CLI Unicode paths can depend on the active code page. GUI cancellation, cross-platform packaging, malformed-input coverage, fuzzing, and sanitizer coverage need more work.

## Roadmap

- ART/emulator/device regression tests across Android API versions.
- Linux/macOS and multi-compiler CI, sanitizer runs, and parser fuzzing.
- Better diagnostics for keep rules, reflection, JNI, and named resources.
- Size, build-time, startup, and runtime benchmarks.
- GUI cancellation/recovery and safer output replacement.
- Exported CMake targets and a more stable public library API.

## Contributing

Issues and PRs are welcome. For a bug report, include the platform, compiler, configuration, effective seed, and a minimal reproducer you can share. Do not upload private applications, signing keys, or sensitive mappings.

Keep a PR focused on one change and add a regression test for a fix. For bytecode transformations, explain the affected instructions, register types, exception behavior, and size/performance impact. Run the relevant tests and the full suite, and note any device or platform behavior you could not check. Discuss larger changes in an issue first.

## License and acknowledgments

Birch is released under the [MIT License](LICENSE).

The GUI uses [Dear ImGui](ImGUI/imgui-1.93.0/LICENSE.txt) by Omar Cornut and contributors and [GLFW](ImGUI/glfw-3.4/LICENSE.md) by Marcus Geelnard, Camilla Löwy, and contributors. ZIP compression and PNG output use [zlib](licenses/ZLIB.txt) by Jean-loup Gailly, Mark Adler, and contributors. These dependencies retain their own licenses.

Thanks to their maintainers and to the authors of the compilers, CMake, and Android tooling and format documentation used by this project.
