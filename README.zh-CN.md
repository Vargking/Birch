# Birch

简体中文 · [English](README.md)

Birch 是一个使用 C++20 编写的 Android DEX 修改与 APK 混淆项目，分为两个主要模块：**BirchDex** 提供 DEX 修改库，**BirchGuard** 在此基础上实现配置驱动的混淆流水线。

项目直接处理 DEX 指令和 APK 内部结构，不会先反编译成 Java，也不需要重建 Android 工程。生成的 APK 未签名，需要另外完成签名。

## 模块划分

### BirchDex：DEX 修改库

BirchDex 提供 DEX 文件模型、构造与写回能力，以及改写字节码所需的分析工具。如果只是读取指令、生成类、替换方法体或重新分配多个 DEX 中的类，可以直接使用这个库，不必运行 BirchGuard 的混淆流水线。

CMake target 为 `BirchDex`，命名空间为 `birch::dex`，公共头文件位于 [include/birch/dex](include/birch/dex)。

- **解析与检查。** `DexFile::Parse` 读取文件头、各类 ID 表、类定义、class data 和 map list，提供 descriptor、方法签名、字段、字符串和原始字节访问。解析异常带有错误码和字节偏移，方便定位损坏的数据。
- **构造与克隆。** `DexBuilder` 根据 `ClassSpec`、`MethodSpec`、`MethodBodySpec` 构造 DEX。方法体使用 code unit 和符号引用补丁，调用者不必预先确定最终的字符串、类型或方法 ID。`DexClassCloner` 把已有类转换成构造模型，并保留已支持的注解、静态初始值、异常处理和调试信息。
- **改写与重定位。** 字符串替换、调试信息移除、ID 重映射、指令替换和完整方法体替换分别有对应接口。写回时重定位受影响的数据和代码地址，更新引用并重算校验值，因此不局限于等长二进制补丁。
- **字节码分析。** 指令解码和 `MethodIr` 提供基本块与控制流边。`ControlFlowGraph`、类型分析、`MethodLiveness`、异常区域分析和 monitor 深度分析用于判断一段代码能否安全改写。
- **多 DEX 处理。** `DexProgram` 表示一组 DEX。链接与继承检查用于解析跨文件关系；分区器统计每个类实际引用的 ID 集合，按配置上限分组，再由 `RepartitionProgram` 克隆并重建为多个 DEX 文件。
- **验证。** 结构、指令、类型、校验值、规范排序、链接和继承检查分别覆盖不同问题。它们是静态检查，不是 Android 运行时的替代实现。

`DexFile` 不是一个修改后调用 `Write()` 就会自动重新序列化的可变对象树。`Write()` 返回保留的字节，因此不做修改的解析/写回可以保持逐字节一致。具体改写接口和 builder 返回新的字节缓冲区；继续编辑时，应重新解析这份结果。

可从 [dex_file.h](include/birch/dex/dex_file.h)、[builder.h](include/birch/dex/builder.h)、[remap.h](include/birch/dex/remap.h) 和 [cloner.h](include/birch/dex/cloner.h) 开始阅读。库本身不依赖 BirchGuard、GUI 或 APK 配置。

### BirchGuard：DEX / APK 混淆流水线

BirchGuard 将 BirchDex 提供的底层能力组织成应用级处理流程：确定哪些类允许改动，安排各个变换，同步跨文件引用，并在输出前检查结果。

实现主体是 `BirchGuardLib` 静态库，命名空间为 `birch::guard`。名为 `BirchGuard` 的可执行文件是它的命令行前端，不是另一套混淆引擎。

BirchGuard 主要负责：

- **配置与保护范围。** 解析 JSON，校验 pass 参数，用 DEX descriptor 模式选择类，并执行 keep 规则。重命名、是否包含成员、是否允许代码变换可以分别控制。
- **变换规划与执行。** 运行类/方法级变换，生成辅助代码，将模型改动转换为 DEX 指令，再执行控制流、字符串、常量和元数据变换。
- **全局重命名。** 为全部 DEX 建立统一映射，处理已识别的名称查找和访问约束，同步受支持的反射调用点、二进制 XML 和类列表。
- **APK 与资源处理。** 读取和重建 ZIP 条目，改写受支持的 manifest、资源引用，处理 DEX 布局与可选分区，移除修改后已经失效的签名。
- **验证与报告。** 限制体积增长和方法大小，检查最终 DEX、链接及布局，输出名称映射、技术报告和进度事件。

公共入口是 [GuardPipeline](include/birch/guard/pipeline.h)。通过 `FromJson` 或 `FromConfig` 创建流水线，再调用 `InspectApk`、`TransformDex` 或 `TransformApk`。带 `ProgressSink` 的重载可将进度接入其他程序。

项目提供的几个前端共用这些库：

| Target | 用途 |
| --- | --- |
| `BirchGuard` | 按 JSON 配置检查和转换 DEX / APK |
| `BirchGuardGUI` | 基于 Dear ImGui、GLFW 和 OpenGL 3 的桌面界面 |
| `Birch` | DEX map、CFG、验证、CFF 审计与分区诊断 |
| `BirchLinkageAudit` | 只读 APK / DEX 链接审计，可加载 framework 元数据 |

依赖方向为：前端 → `BirchGuardLib` → `BirchDex`。编写自己的字节码编辑器时链接 `BirchDex`；需要整套配置化混淆流程时链接 `BirchGuardLib`。

## 构建

需要以下环境：

- CMake 3.22 或更新版本。
- 支持 C++20 的编译器和 zlib 开发文件。
- Ninja，供下方命令使用。
- 构建 GUI 时还需要 C 编译器、线程支持和桌面 OpenGL 开发环境。

Dear ImGui 1.93.0 和 GLFW 3.4 的源码已放在 `ImGUI/` 中。构建过程不会自动下载缺失依赖。

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBIRCH_BUILD_GUI=ON -DBIRCH_BUILD_TESTS=ON
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure -j 3
```

只需要 CLI 时，在单独的构建目录中配置 `-DBIRCH_BUILD_GUI=OFF`。不构建测试可设置 `-DBIRCH_BUILD_TESTS=OFF`。

Windows 已使用 MinGW-w64/GCC 验证构建。运行时需要能从 `PATH` 找到编译器运行库 DLL。使用 Visual Studio 生成器时省略 `-G Ninja`，构建命令增加 `--config Release`，CTest 增加 `-C Release`；这套工具链仍需单独验证。

找不到 zlib 时，可设置 `-DZLIB_ROOT=<安装目录>`，或指定 `ZLIB_INCLUDE_DIR` 和 `ZLIB_LIBRARY` 的完整路径。MinGW 回退查找只会使用编译器目录中实际存在的 zlib 头文件和库。

Linux GUI 需要对应 GLFW X11 / Wayland 后端和 OpenGL 的开发包。不使用 Wayland 可设置 `-DGLFW_BUILD_WAYLAND=OFF`。Linux、macOS 还需要更完整的构建与运行验证。

### 在其他项目中使用库

假设 Birch 位于 `external/Birch`：

```cmake
set(BIRCH_BUILD_GUI OFF CACHE BOOL "")
set(BIRCH_BUILD_TESTS OFF CACHE BOOL "")
add_subdirectory(external/Birch)

target_link_libraries(my_tool PRIVATE BirchDex)
# 使用完整混淆流水线时，改为链接 BirchGuardLib。
```

公共头文件路径由 target 自动传递。`BirchGuardLib` 还会链接 BirchDex 和 zlib。目前即使应用只链接 BirchDex，顶层 CMake 仍会查找 zlib。项目尚未提供安装后的 `find_package(Birch)` 导出接口，也没有稳定 ABI 承诺。

### 安装与打包

```sh
cmake --install build --prefix install
cpack --config build/CPackConfig.cmake -G ZIP -B dist
```

多配置生成器需要在安装时增加 `--config Release`，CPack 增加 `-C Release`。ZIP 包含安装后的工具、已启用的 GUI、库、头文件、配置和依赖许可。编译器及 zlib 运行库不会自动打入包中。

## 使用

### 配置文件

仓库提供三个起始配置：

| 文件 | 用途 |
| --- | --- |
| [rename_only.json](configs/rename_only.json) | 以重命名为主 |
| [resource_only.json](configs/resource_only.json) | APK 资源变换 |
| [release_full.json](configs/release_full.json) | 高强度配置，会带来明显的代码增长 |

使用前，将 `scope.protect` 中的 `Lcom/example/**;` 替换为应用自身的 DEX descriptor 模式。对外部依赖名称或行为的类添加 keep 规则。`scope.keep` 优先于 protect。

没有在 JSON 中列出的 pass 会继承引擎默认值。文件名中的 `_only` 不会自动关闭其他 pass；需要严格限定变换时，应显式关闭不需要的项目。未知字段和 pass ID 会被拒绝。

`android_dex` 可选，用于提供 Android framework 的继承和方法解析信息，应与目标 Android API 对应。framework 只参与分析，不会复制进输出。JSON 中的相对路径以进程当前工作目录为基准，不是以 JSON 文件所在目录为基准。

### 命令行

在项目根目录执行。Windows 下可执行文件带 `.exe` 后缀。

```sh
./build/BirchGuard --list-passes
./build/BirchGuard --config configs/rename_only.json --inspect-apk input.apk
./build/BirchGuard --config configs/rename_only.json --transform-apk input.apk output-unsigned.apk
./build/BirchGuard --config my-dex.json --transform-dex input.dex output.dex
```

独立 DEX 输出不支持 APK 资源选项。需要同时关闭两个资源开关（`resources.rename_files`、`resources.rename_names`）和两个资源 pass（`resources.file_rename`、`resources.name_rename`）。

诊断命令：

```sh
./build/Birch input.dex --verify
./build/Birch input.dex --scan-cfg
./build/Birch input.dex --map
./build/Birch input.dex --audit-cff
./build/BirchLinkageAudit input.apk
./build/BirchLinkageAudit input.apk android.dex --verbose
```

转换会生成目标 APK / DEX、`<输出路径>.techniques.txt`，以及按配置启用的 mapping 文件。技术报告记录有效 seed、实现说明、已统计的变换次数和兼容性警告。开启某个 pass 不代表一定存在可处理的位置；`not instrumented` 表示该项没有精确计数。

mapping 和报告应与发布的应用分开保存。输入、输出、mapping、报告路径不能相同，也不能是指向同一文件的硬链接。CLI 可以覆盖已有输出文件。

退出码：成功为 0，参数错误为 2，解析、转换或验证失败为 1。

### GUI 与 APK 签名

运行 `build/tools/gui/BirchGuardGUI`。界面支持文件选择/拖放、JSON 导入、scope 规则、pass 筛选和强度设置，使用的引擎与 CLI 相同。任务在后台线程执行，期间锁定设置；目前不支持取消和断点续跑。

输出 APK 未签名，需要使用外部 Android SDK 工具完成对齐、签名和验证。项目目前没有内置签名后端。更换证书可能影响应用升级和第三方集成，签名后仍需在目标设备上测试。

## 核心实现

### DEX 改写与最终验证

DEX 指令通过数字 ID 引用字符串、类型、字段、方法和原型。增加一个辅助方法，或改变一个类的 descriptor，都可能影响 ID 排序和指令宽度，因此不能把任意改动都当作原位置的字节替换。

BirchDex 会重建或重定位受影响的区段，并应用 ID 映射与地址映射。代码改写还要处理分支偏移、switch 和数组 payload、try 范围、handler 地址及调试地址。规范化重映射恢复 ID 表要求的排序，字节布局确定后再生成校验值。

BirchGuard 负责把这些操作串起来：分析 scope 与运行时依赖，执行模型和指令变换，应用统一重命名，按需重新分区 DEX，然后重建 APK。最终字节会再次解析，检查结构、类型、方法大小、跨 DEX 链接，以及旧版 Android 的 DEX 装载布局。

相关代码：[remap.cpp](src/birch/dex/remap.cpp)、[builder.cpp](src/birch/dex/builder.cpp)、[pipeline.cpp](src/birch/guard/pipeline.cpp)。

### 跨 DEX 重命名

重命名不是逐个 DEX 各自生成名字，而是为全部输入建立一份计划。例如，`classes2.dex` 中引用的方法，必须与 `classes.dex` 中重命名后的定义保持一致。

规划器先收集必须保留的名称，建立方法冲突关系，再分配不会引入已知查找冲突的新名称。framework 中已有的名称也会预留，防止一个普通方法改名后意外成为 override。如果移动包会破坏包内可见性访问，类可以只修改简单类名，继续留在原包中。

对已识别的反射调用点，流水线会提前规划名称映射。模型变换新增类和方法时锁定这些已使用的映射，最终重命名阶段再检查是否保持一致。受支持的 manifest、资源 XML、service 列表和其他类列表也同步使用这份映射。

这不能解决任意动态拼接名称。JNI、序列化、插件和应用自定义的名称查找仍可能需要显式 keep 规则。

相关代码：[rename_planner.cpp](src/birch/guard/rename_planner.cpp)、[runtime_contract.cpp](src/birch/guard/runtime_contract.cpp)、[package_access.cpp](src/birch/guard/package_access.cpp)。

### 类型感知的控制流平坦化

控制流平坦化将可处理的基本块之间的直接跳转改成状态更新和分发跳转。BirchGuard 使用编码后的 state / selector、多级 keyed dispatcher、joint token 检查和生成的运行时 barrier。干扰状态另有编码边、局部解码器和分片 switch，组成独立的控制流图。

难点不只是改变跳转方向。共享分发器会增加控制流汇合点：同一个寄存器在一条路径上是整数、另一条路径上是对象引用，汇合后就可能使原本有效的 DEX 无法通过类型验证。

因此，`CffTypeDomains` 按兼容的寄存器类型状态对出口分组。启用活跃性投影时，只有能够证明在下一次读取前会被覆盖的寄存器，才可以不参与比较。分组和活跃性分析会反复细化，直到分组不再变化，避免新增共享路径后漏掉重新变为活跃的值。未初始化引用和异常相关状态还会施加额外限制。

包含显式 `monitor-enter` / `monitor-exit` 的方法不共享类型域：寄存器类型相同，并不能证明每条路径持有的是同一把锁。

相关代码：[control_flow_flattener.cpp](src/birch/guard/control_flow_flattener.cpp)、[cff_type_domains.cpp](src/birch/guard/cff_type_domains.cpp)、[cff_transition_encoder.cpp](src/birch/guard/cff_transition_encoder.cpp)。

### 方法拆分与代码预算

平坦化、常量展开和干扰图可能把一个不大的源方法扩展成很大的输出方法。BirchGuard 为此使用几种区域提取方式：

- `ConstantProgramOutliner` 将完整的常量运算程序移入同类辅助方法，保留原有运算，带类型约束的运行时 barrier 仍留在调用点。
- `LinearRegionOutliner` 提取符合条件的直线代码区域，要求区域出口的活跃值保持不变。
- `CfgRegionPlanner` 与 `CfgRegionOutliner` 处理单入口、单后继的区域，区域内部可以有分支和循环。活跃输入变成带类型的参数，支持的活跃输出通过返回值或重建常量恢复。

提取不能拆开 `invoke` / `move-result`，不能让外部边进入区域内部，也不能跨越不兼容的异常处理上下文。monitor 指令不会被移入辅助方法。处于同一 try 上下文内的区域可以替换成仍由原 handler 覆盖的调用，锁留在调用者中。生成的辅助方法仍会参与后续保护和验证。

`CffCodeBudget` 在提交布局前逐项统计指令、转移代码、干扰状态、payload 和对齐，再核对实际发射尺寸。专门的预算异常可以触发有限次数的提取和重新规划；CFG 细分从指令展开前的源状态开始，不会在失败结果上继续叠加变换。

仓库的 full 配置请求 1024 个干扰状态。完整强度下，每个方法还有 16000 code unit 的限制；配置更低时使用更低值。一个 code unit 是 16 位，所以将 `max_code_units_per_method` 设为 65000 也不会取消这个内部上限。完整 CFF 在确定布局前就使用 `const-string/jumbo`，提前计入字符串 ID 可能扩宽带来的尺寸。

重命名和重新分区后，`OutputCodeBudget` 再检查实际序列化的方法大小，并把改名后的类还原到原 scope 判断。仍然超限会报错，这一最终检查不会再拆分方法或降低请求的强度。

相关代码：[cff_code_budget.cpp](src/birch/guard/cff_code_budget.cpp)、[cff_partition_planner.cpp](src/birch/guard/cff_partition_planner.cpp)、[output_code_budget.cpp](src/birch/guard/output_code_budget.cpp)。

### 字符串与常量

字符串变换先将 DEX modified UTF-8 解码为 UTF-16 code unit，而不是按普通 UTF-8 字节处理 Java 字符串，因此能够保留内嵌 NUL 和代理对的表示。

每个字符串根据内容和 seed 的稳定哈希，从四种 XOR / 加法模式中选择一种，并派生三个 16 位密钥。基础变换之后还有八轮与字符位置有关的混合：

```text
x = base_transform(unit, index, k1, k2, k3)
for r = 0 .. 7:
    x ^= uint16(index + 17 * r)
    x += uint16(k1 + 0x1357 * r)
    x ^= uint16(k2 ^ (k3 + 0x246d * r))
    x &= 0xffff
```

变换结果存入生成的 byte array payload。原来的字符串加载指令改为调用辅助方法；辅助方法按相反顺序执行逆运算，用 `char[]` 构造 `String`，再清理临时数组。完整字符串会调用 `intern()`，保持 `const-string` 的规范实例语义；拆分后的私有片段不会单独 intern。

常量变换也会将受支持的加载指令替换为 XOR / 加法程序，并加入带类型约束的 barrier。处理时需要区分整数零与空引用，保留后续指令要求的操作数类型。

这些处理改变了静态表示，但还原逻辑和密钥仍在应用中，不能用来替代服务端保管秘密。

相关代码：[model_strings.cpp](src/birch/guard/model_strings.cpp)、[dex_lowering.cpp](src/birch/guard/dex_lowering.cpp)、[constant_program_outliner.cpp](src/birch/guard/constant_program_outliner.cpp)。

### 资源改写

资源规划使用原始 DEX 字符串，在字符串变换隐藏字面量引用之前完成。它会检查 ARSC 字符串、资源名称/路径 API 引用、assets、是否存在 native 库，以及 overlay 元数据。

允许改名的资源文件会获得由 16 个字典 token 组成的新文件名，并检查冲突。目录和扩展名不变，`.9.png` 会作为完整后缀保留。ZIP 条目名与 ARSC 路径一起更新，受支持的二进制 XML 路径引用也同步修改。条目重命名保留 ZIP 顺序，之后检查新路径是否同时存在于 ARSC 和归档中。

没有检测到名称依赖时，资源 key pool 中的名称可以替换为 `BirchGuard`；资源 ID、类型名和面向用户的值不会被主动改写。动态查找、路径字面量、assets、native 代码或 overlay 可能导致某个资源、甚至整类变换被保留。这些检查是保守的启发式判断，不是对 native 和动态加载代码的完整分析。

相关代码：[resource_obfuscator.cpp](src/birch/guard/resource_obfuscator.cpp)、[arsc.cpp](src/birch/guard/arsc.cpp)、[axml.cpp](src/birch/guard/axml.cpp)。

### Seed 与复现

配置中的 `seed` 不一定等于最终有效 seed。启用构建参数随机化时，部分配置和 pass 设置会混入种子；非可复现模式还会加入运行时熵。

需要复现报告中的参数时，在 JSON 根对象中加入记录下来的种子：

```json
"effective_seed": "16919314818285478265"
```

同时保留原输入、配置、framework 和引擎版本。这会覆盖种子派生过程，不保证不同引擎版本或环境下的输出逐字节相同。根级和逐 pass 的 seed 支持十进制 `uint64` 字符串；大于 9007199254740991 的值必须使用字符串，避免 JSON 数值精度损失。

## 测试

回归输入由代码构造或在运行时生成，不需要第三方应用 APK 或 framework DEX。合成 APK 用于检查格式和流水线行为，不是可安装应用。

```sh
ctest --test-dir build --output-on-failure
ctest --test-dir build -L cff-budget --output-on-failure
ctest --test-dir build -LE extended --output-on-failure -j 3
```

完整测试包含较慢的 `extended` 项。`cff-budget` 用于选择代码预算、类型域、活跃性、区域提取、异常和 monitor 相关回归。Release 测试也保留断言。测试解释器只实现用例所需的指令和 API 行为，不等同于完整 ART。

## 已知限制

- 静态验证不能替代 Android 设备上的安装、启动、资源、异常路径和性能测试。
- 动态反射、JNI、序列化、插件、资源按名查找和应用自校验可能在变换后失效。
- 高强度配置会增加文件体积、调用深度、构建时间和运行开销，部分输入会因安全检查或预算超限被拒绝。
- 不提供 AAB / JAR 转换、原生代码保护、通用字节码虚拟机或内置 APK 签名。`crypto`、`array_virtualization` 等 pass 名称对应具体实现，不代表具备这些完整能力；可参阅 [technique_catalog.cpp](src/birch/guard/technique_catalog.cpp)。
- Windows CLI 的 Unicode 路径处理可能受系统代码页影响。GUI 取消、跨平台打包、畸形输入覆盖、fuzz 和 sanitizer 覆盖仍需完善。

## 后续计划

- 建立覆盖多个 Android API 的 ART、模拟器和真机回归。
- 增加 Linux / macOS、多编译器 CI、sanitizer 和解析器 fuzz。
- 完善 keep 规则、反射、JNI 和资源名称依赖的诊断。
- 建立体积、构建时间、启动时间和运行性能基准。
- 支持 GUI 取消、任务恢复和更安全的输出替换。
- 提供 CMake 导出 target，逐步稳定公共库 API。

## 参与贡献

欢迎提交 issue 和 PR。报告问题时请提供平台、编译器、配置、有效 seed 和可以公开的最小复现，不要上传私有应用、签名密钥或敏感 mapping。

一个 PR 尽量只处理一件事，修复问题时补上回归测试。涉及字节码变换，请说明受影响的指令、寄存器类型、异常行为，以及体积和性能变化。提交前运行相关测试和完整测试，并注明尚未验证的设备或平台。较大的改动可以先开 issue 讨论。

## 许可与致谢

Birch 使用 [MIT 许可证](LICENSE)。

GUI 使用 Omar Cornut 及贡献者维护的 [Dear ImGui](ImGUI/imgui-1.93.0/LICENSE.txt)，以及 Marcus Geelnard、Camilla Löwy 及贡献者维护的 [GLFW](ImGUI/glfw-3.4/LICENSE.md)。ZIP 压缩和 PNG 输出使用 Jean-loup Gailly、Mark Adler 及贡献者维护的 [zlib](licenses/ZLIB.txt)。这些依赖保留各自的许可。

感谢上述项目的维护者，以及本项目所使用的编译器、CMake、Android 工具和格式文档的作者。
