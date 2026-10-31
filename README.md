# Birch / BirchGuard

A C++20 Android DEX/APK transformation and obfuscation toolkit with a CLI, desktop GUI, and static verification.

C++20 编写的 Android DEX/APK 变换与混淆工具链，提供命令行、桌面 GUI 和静态验证。

**Research-oriented software: successful transformation does not prove Android runtime compatibility or resistance to reverse engineering.**

**研究型工具：转换成功不等于 Android 运行时兼容性验证，也不构成抗逆向效果保证。**

## GitHub description / 项目描述

English About text:

> A C++20 Android DEX/APK obfuscation toolkit with a CLI, desktop GUI, control-flow transformations, and static verification.

中文 About 文案：

> C++20 编写的 Android DEX/APK 混淆工具链，提供命令行、桌面 GUI、控制流变换与静态验证。

Suggested topics / 建议标签：`android`, `dex`, `apk`, `obfuscation`, `cpp20`, `control-flow`, `imgui`, `cmake`.

## Contents / 导航

- [中文说明](#中文说明)：实现原理、构建、使用、限制、路线图、贡献和许可。
- [English documentation](#english-documentation): implementation, build, usage, limitations, roadmap, contributions, and licensing.

## 中文说明

### 1. 项目定位与能力边界

Birch 是项目名；BirchGuard 是保护流水线和主要用户入口。项目直接处理 DEX，以及 APK 中的 DEX、二进制 AndroidManifest.xml、resources.arsc 和 ZIP 条目，不依赖反编译为 Java 再重新编译。

| 组件 | 职责 |
| --- | --- |
| BirchDex | DEX 解析/构建/写回、指令与 CFG、类型和活跃性分析、验证、链接及分区基础设施 |
| BirchGuardLib | 配置与 scope、变换调度、控制流保护、跨 DEX 重命名、资源处理及报告 |
| BirchGuard | 配置驱动的 APK/DEX 检查和转换 CLI |
| Birch | DEX map、CFG、验证、CFF 审计和 APK 检查等低层诊断 CLI |
| BirchLinkageAudit | APK/DEX 的只读链接审计，可额外提供 Android framework DEX |
| BirchGuardGUI | Dear ImGui + GLFW + OpenGL 3 桌面界面 |

已实现的保护包括重命名、受限结构变换、类型域感知控制流平坦化、不透明谓词、字符串与常量变换、伪代码和资源文件/名称混淆。部分 pass 只适用于可证明安全的指令、类型或结构，并不保证每个方法都应用同样的变换。

本项目不是完整 Android 应用构建系统、AAB/JAR 转换器、原生代码保护器、通用字节码虚拟机或加密壳。pass 名称中的 `crypto`、`cross_process`、`encrypted_paths`、`array_virtualization` 不代表标准密码协议、独立进程、完整类加载壳或完整 VM。实际实现以源码中的 [technique_catalog.cpp](src/birch/guard/technique_catalog.cpp) 和每次输出的技术报告为准。

### 2. 核心实现原理

#### 2.1 解析、分析与写回

流水线读取 APK ZIP、manifest、资源表及一个或多个 DEX，解析配置和保护范围，建立类型、继承、引用和控制流信息。模型级变换可以生成 helper 类/方法，随后降低到 DEX 指令；全局重命名规划同步更新跨 DEX 引用以及已支持的 manifest/资源引用。最终重映射 ID、布局和写回，并执行结构、类型、代码预算、链接与旧版 Android DEX 装载约束检查。

简化顺序：

```text
输入解析 → scope/keep 与链接信息 → 变换规划与模型改写
        → DEX lowering / CFF / helper 生成 → 全局重命名与资源同步
        → 重映射 / 可选多 DEX 分区 → 最终验证 → 输出与报告
```

`android_dex` 是可选的 Android framework 元数据，用来辅助判断外部继承和 override 合同，不会作为应用代码复制进输出。应由使用者提供匹配目标 Android API 的 framework DEX；缺失或不匹配会限制分析覆盖与重命名安全性。

#### 2.2 重命名与运行时合同

类、方法、字段和包的名称由全局规划生成，并维护跨 DEX 引用闭包。规划器对 framework override、包可见性、native/JNI 和可识别的反射合同采取保守处理；动态拼接名称、第三方插件、序列化、JNI 绑定等仍可能需要明确的 keep 规则。

scope 使用 DEX descriptor 模式，例如 `Lcom/example/**;`。keep 匹配优先于 protect，匹配 keep 的类型不进入常规保护；保护规则可用 `allow_renaming`、`allow_code_transforms`、`include_members` 限制行为。多个匹配 protect 规则中任一相关标志为 false，都会阻止该类的对应行为。引擎生成的保留命名空间有专门的 scope 处理，helper 仍可参与后续保护。

#### 2.3 类型域感知的控制流平坦化

控制流保护结合 CFG、寄存器类型帧与活跃性分析，把兼容块放入类型域，使用多级 keyed dispatcher、编码 state/selector、joint token 和运行时 barrier 改写转移。未知类型、未初始化对象、异常入口等不安全状态不能任意合并。死图包含编码转移、局部解码岛与分片 switch，而不只是大量指向同一位置的空 goto。

长方法通过 ConstantProgramOutliner、LinearRegionOutliner 和 CfgRegionPlanner / CfgRegionOutliner 提取符合合同的区域。区域必须满足入口、continuation、类型、live-in/live-out、异常和 monitor 约束；不能拆开 `invoke/move-result`，不能任意跨 try 边界或移动 handler/monitor。锁保持在 caller；不能证明安全的区域会被拒绝。

CffCodeBudget 在发射前精确统计业务指令、转移、死图、payload 与对齐，发射后再次核对实际尺寸。CffPartitionPlanner 在专用预算失败时从 materialization 前的源状态重新规划，定向提取/分片并重跑，重试有上限。它不会通过偷偷降低强度、减少死状态或更换 `seed` 来掩盖失败。

最高强度策略包含 1024 死状态及内部 **16000 code-unit** 门禁。一个 DEX code unit 是 16 位，不是一个字节；配置中的 `max_code_units_per_method: 65000` 不会关闭这个更严格的内部限制。完整 CFF 在布局固定前使用 `const-string/jumbo`，将真实尺寸计入预算，避免后续字符串 ID 重排突然扩宽指令。

独立的 OutputCodeBudget 在重命名与最终分区之后检查 serialized code-item 大小，通过 rename map 还原原 owner 后判断 scope。它是最终拒绝门禁，不在出口偷偷重新分片；无法满足约束时明确失败。

#### 2.4 字符串、常量与数据变换

字符串使用自定义可逆 UTF-16 变换：4 种 XOR/add 基础模式，加 8 轮逐字符混合，再生成运行时逆变换。**它不是 AES/ChaCha，不提供密码学保密性；密钥和还原逻辑都随应用分发。**

常量可变成 XOR/add 程序，结合类型化 barrier、布尔算术、受限数组/枚举变换及元数据噪声。覆盖范围取决于支持的指令和安全合同；并非所有字符串、常量或资源都会被改写。

#### 2.5 资源与 APK 一致性

文件混淆生成经过碰撞检查的 16-token Unicode basename，同步更新 ZIP 条目与 ARSC 路径，保留扩展名、`.9.png` 语义和原 ZIP 条目顺序。安全的资源 package key-pool 名称可变为 BirchGuard；资源 ID、类型名称与面向用户的文本不被故意改变。

按名查询、`getIdentifier`、反射、native、overlay 或直接路径字面量等证据会触发保守保留。保留原因和兼容性警告写入报告，不能承诺所有 APK 都能安全地重命名所有资源。

#### 2.6 随机化与可复现

`seed` 是基础输入。开启 `strength.build_parameter_randomization` 且允许参数随机化时，引擎会混合配置；`strength.reproducible_output=false` 还会混入运行时熵。同一份 JSON 不一定生成相同输出。

复现已记录的有效参数可在根配置加入：

```json
"effective_seed": "16919314818285478265"
```

保留原输入、配置、framework 和引擎版本，不需要关闭 pass 或降低强度。正常随机构建时移除此项。`seed`、`effective_seed` 和逐 pass `seed` 支持 `uint64` 十进制字符串；超过 `9007199254740991` 必须用字符串，以避免 JSON 数值精度损失。`target_analysis_cost_weeks` 只是策略启发式输入，不是实际逆向耗时承诺。

### 3. 源码布局与依赖

```text
CMakeLists.txt          构建、测试、安装与 CPack 配置
main.cpp               低层诊断 CLI
include/birch/         公共头文件
src/birch/dex/         DEX、CFG、分析、验证与分区
src/birch/guard/       混淆、lowering、APK/资源与报告
src/birch/io/          文件与 APK 条目 IO
src/birch/utils/       哈希与通配符工具
tools/                 CLI、审计与开发工具
tools/gui/             GUI、配置模型与后台任务
configs/               通用 JSON 配置
tests/                 合成输入回归测试及其支持代码
ImGUI/                 vendored ImGui / GLFW 构建依赖
licenses/              第三方许可说明
```

源码分发只需要核心代码、依赖、配置和测试源码。应用样本、framework 二进制、历史版本说明、映射、签名密钥与构建产物不应提交；`.gitignore` 已排除这些类别以及未使用的第三方示例/后端。ignore 规则不是物理删除，也不会删除已经跟踪的文件。第三方许可文件即使是 Markdown 也应保留。

### 4. 从源码构建

需要 CMake **3.22+**、支持 C++20 的编译器、zlib 开发头文件与库；GUI 还需要 C 编译器、线程支持和桌面 OpenGL 开发环境。ImGui 1.93.0 与 GLFW 3.4 源码随项目提供，不会自动联网拉取缺失依赖。

在已配置编译器、Ninja 和 zlib 的终端中执行：

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBIRCH_BUILD_GUI=ON -DBIRCH_BUILD_TESTS=ON
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure -j 3
```

Windows 可使用 MinGW-w64/GCC；运行时需要其 DLL 可被系统找到（例如编译器 bin 在 PATH 中）。使用 Visual Studio 生成器时省略 `-G Ninja`，构建加 `--config Release`，测试加 `-C Release`；这条工具链需自行验证，不代表所有编译器组合均已测试。

找不到 zlib 时向 configure 命令提供 `-DZLIB_ROOT=路径`，或 `-DZLIB_INCLUDE_DIR=头文件目录` `-DZLIB_LIBRARY=库文件完整路径`。只有实际存在的 MinGW 配套 zlib 才会被 fallback 使用。

Linux GUI 需要 GLFW 所启用的 X11/Wayland 开发包及 OpenGL；不需要 Wayland 时可在 configure 加 `-DGLFW_BUILD_WAYLAND=OFF`。macOS 需要相应开发工具和 OpenGL 3.2 core 支持。本地验证以 Windows 为主，不把 Linux/macOS 源码分支视为已验证的发行支持。

只构建 CLI：

```sh
cmake -S . -B build-cli -G Ninja -DCMAKE_BUILD_TYPE=Release -DBIRCH_BUILD_GUI=OFF -DBIRCH_BUILD_TESTS=ON
cmake --build build-cli --parallel 4
ctest --test-dir build-cli --output-on-failure
```

单配置构建的主要输出在 `build/`，GUI 在 `build/tools/gui/`；多配置生成器会增加 `Release/` 等子目录。BirchDex 和 BirchGuardLib 可作为同一源码树内的静态库 target 使用。目前没有稳定 ABI 或完整的已安装 `find_package(Birch)` 导出接口。

安装及标准 ZIP 打包：

```sh
cmake --install build --prefix install
cpack --config build/CPackConfig.cmake -G ZIP -B dist
```

多配置构建分别追加 `--config Release` / `-C Release`。安装包含 CLI、启用时的 GUI、两项核心静态库、公共头文件、配置和许可。CPack ZIP 是安装产物，不是完整源码归档；不会自动捆绑编译器/zlib 运行时，请在干净机器检查依赖。旧的应用样本打包脚本不属于本源码分发流程。

### 5. 配置与命令行

先执行 `build/BirchGuard --list-passes`（Windows 加 .exe）查看当前 pass ID。三个配置位于 `configs/`：

| 配置 | 用途与注意事项 |
| --- | --- |
| [rename_only.json](configs/rename_only.json) | 以重命名为主的起点；仍继承未列出的引擎默认值 |
| [resource_only.json](configs/resource_only.json) | 以 APK 资源变换为主的起点；不是独立 DEX 配置 |
| [release_full.json](configs/release_full.json) | 高强度、高增长的研究配置，不是适合所有应用的生产默认值 |

JSON 中未列出的 pass 继承引擎默认值，文件名中的 `_only` 不会自动关闭其他 pass。需要严格白名单时逐项显式关闭不需要的 pass。未知字段、pass ID 和非法参数会被验证器拒绝。

使用前将 `scope.protect` 的 `Lcom/example/**;` 替换为自己的应用 descriptor；根据需要填写 `android_dex`、keep 规则和独立的 mapping 路径。JSON 内相对路径基于**进程当前工作目录**，不是 JSON 文件所在目录。通用配置不包含应用或 framework 样本。

以下 Windows PowerShell 示例在项目根目录执行，`input.apk` / `input.dex` 由使用者提供：

```powershell
.\build\BirchGuard.exe --list-passes
.\build\BirchGuard.exe --config configs/rename_only.json --inspect-apk input.apk
.\build\BirchGuard.exe --config configs/release_full.json --transform-apk input.apk output-unsigned.apk
.\build\BirchGuard.exe --config my-dex.json --transform-dex input.dex output.dex
.\build\Birch.exe --help
.\build\Birch.exe input.dex --verify
.\build\Birch.exe input.dex --scan-cfg
.\build\BirchLinkageAudit.exe input.apk
```

Linux/macOS 使用 ./build/BirchGuard 等可执行路径。独立 DEX 任务须关闭 `resources.rename_files`、`resources.rename_names` 及 `resources.file_rename` / `resources.name_rename` 两个 pass。GUI 会拒绝不兼容的资源设置。

其他诊断入口包括 `Birch input.dex --map`、`--audit-cff`，`Birch --partition <目录>`、`Birch --inspect-apk <APK>`；审计支持 `BirchLinkageAudit <APK或DEX> [android.dex] [--verbose]`。`BirchGuard --config <JSON> --prepare-fake-dex <输出DEX>` 可生成研究用伪 DEX，不是可安装应用。

正常成功返回 0，错误参数返回 2，解析/转换/验证失败返回 1。Windows CLI 使用窄字符 argv，某些系统代码页下的 Unicode 路径可能有问题；必要时使用 ASCII 路径或 GUI。

转换会输出目标 APK/DEX、`<输出路径>.techniques.txt`，以及 `write_mapping=true` 时指定的 mapping。报告记录有效 `seed`、实际实现、已记录计数和兼容警告；`not instrumented` 或零计数不是保护已生效的证据。mapping 与报告可能暴露名称对应关系和构建参数，应私下保存，不随受保护应用发布。

输入、输出、mapping 和报告不得重叠，包括硬链接别名。CLI 可以替换已有输出，请事先备份；GUI 会请求替换确认。

### 6. GUI 与 APK 签名

运行 `build/tools/gui/BirchGuardGUI`。界面为英文桌面应用，采用 iOS 风格视觉，并不是 iOS 应用。支持路径输入/拖放、JSON 导入、scope、framework、mapping、pass 筛选和强度调整。Balanced / Strong / Maximum 的 Apply preset 会重新开启兼容 pass；`debug_local_noise` 与 `debug_info_removal` 互斥。

后台任务使用配置快照与 `std::jthread`，通过受互斥锁保护、最多 2000 条的进度队列更新界面，不从 worker 调用 ImGui。任务期间设置锁定；关闭实时日志不会关闭验证。当前没有取消或断点续跑，任务未完成时关闭窗口会被暂缓；耗时阶段没有可靠百分比。

图形环境可用时可做隐藏窗口检查：

```powershell
.\build\tools\gui\BirchGuardGUI.exe --smoke-test
.\build\tools\gui\BirchGuardGUI.exe --screenshot gui.png
```

这只检查渲染基本可用性，不替代交互、高 DPI 或布局验收。

APK 输出是**未签名 APK**，旧签名会被移除；启用内置签名会报错，目前必须使用外部 Android SDK 工具完成 zipalign、apksigner 签名和签名验证。密钥应属于你或已授权使用，不要将密钥或密码提交到仓库。签名改变可能破坏升级、完整性校验和第三方集成。签名后仍须在目标设备验证安装、启动、核心流程、资源、异常路径和性能。

### 7. 测试与已知缺陷

保留的测试源码使用构造器和运行时生成的合成输入，不要求分发第三方应用 APK、DEX 或 framework。合成 APK 只用于格式/流水线回归，不是可安装应用。Release 测试保留 `assert`，避免因 `NDEBUG` 将断言变为空操作。

```sh
ctest --test-dir build --output-on-failure
ctest --test-dir build -L cff-budget --output-on-failure
ctest --test-dir build -LE extended --output-on-failure -j 3
ctest --test-dir build -L extended --output-on-failure
```

`cff-budget` 覆盖预算、类型域、活跃性、区域提取、异常和锁等；`extended` 当前是较慢的直线区域提取测试。完整 CTest 默认包含这些测试。指令/字符串测试解释器只实现测试所需的语义，不是完整 ART。

目前需要正视的限制：

- 静态验证不能替代 Android ART、模拟器和真实设备回归；没有“全部 Android 版本/全部 APK 兼容”的保证。
- 动态反射、JNI、序列化、插件、资源按名查询和应用自校验仍可能失效；keep 与业务验收是使用者责任。
- 高强度 CFF、helper 和死图会增加体积、调用深度、构建时间及运行开销，可能明确触发预算拒绝；没有统一性能基准或保护强度评分。
- 自定义字符串变换、伪代码与不透明谓词可以被分析或自动化还原，不能作为密码学安全边界。
- 解析器和写回路径尚需更多畸形输入、fuzz 与 sanitizer 覆盖；本地 MinGW 工具链缺少可用 ASan/UBSan runtime，不能声称已通过 sanitizer。
- Linux/macOS、其他编译器及高 DPI GUI 仍需独立验证；CLI Unicode 路径、GUI 取消/恢复及事务式输出体验仍有改进空间。
- 不提供内置 APK 签名、Android SDK/framework 下载、稳定库 ABI 或完整安装包依赖收集。

请仅处理自己拥有或获授权处理的应用；不要把第三方 APK、凭证、个人数据或私有业务逻辑上传到 issue。

### 8. 未来方向

以下是计划与欢迎贡献的方向，不代表已经实现或承诺交付时间：

- 建立 ART/模拟器/真实设备与不同 Android API 的回归矩阵。
- 完善 Linux/macOS/多编译器 CI，以及 ASan/UBSan、静态分析和解析器 fuzz。
- 扩充可移植的合成输入、指令语义与异常/monitor 边界测试。
- 加强动态反射、JNI、序列化及资源按名访问合同的诊断与 keep 校验。
- 建立可复现的体积、启动时间、运行性能和构建耗时基准。
- GUI 取消、任务恢复、更清晰的失败定位与事务式输出。
- 稳定公共 API、CMake 导出 target、构建 presets 与跨平台打包。

### 9. 欢迎贡献 / PR

欢迎 bug report、文档修正、测试用例和 PR。较大变更请先在 issue 中说明目标和兼容性影响。建议流程：

1. 使用最小、可公开的合成输入复现问题，记录编译器、平台、输入特征、完整配置与有效 `seed`；提交前移除路径、名称、mapping 和日志中的敏感信息。
2. 一个 PR 聚焦一项改动，说明变换前后语义、安全合同和可能的体积/性能影响。
3. 为修复增加回归，运行相关测试及完整 CTest；涉及 CFF/分区时运行 `cff-budget`，不要跳过慢测后声称全量通过。
4. 对无法验证的设备、平台或工具链如实说明；适用且可用时补充 sanitizer/静态分析结果。
5. 保留第三方许可；不要引入应用样本、密钥、构建产物或历史版本说明。

### 10. 致谢与许可状态

感谢以下项目及其贡献者：

- **Dear ImGui**：Omar Cornut 及贡献者，MIT；许可见 [ImGui license](ImGUI/imgui-1.93.0/LICENSE.txt)。
- **GLFW**：Marcus Geelnard、Camilla Löwy 及贡献者，zlib/libpng 风格许可；见 [GLFW license](ImGUI/glfw-3.4/LICENSE.md)。
- **zlib**：Jean-loup Gailly、Mark Adler 及贡献者，用于 ZIP 压缩和 GUI PNG 输出；说明见 [zlib notice](licenses/ZLIB.txt)。实际链接的版本由工具链提供。
- CMake、编译器、Android 格式文档及其他开放工具生态。

**项目自身的开源许可证尚待所有者决定，当前没有项目级 LICENSE。公开可见的源码不等于获得使用、修改或再分发授权。** 在正式宣布开源、接受并合并外部贡献之前，应先补充明确的项目许可证与版权信息。第三方依赖继续遵守各自许可，不能因为删减文档而移除其许可声明。

## English documentation

### 1. Purpose and scope

Birch is the project; BirchGuard is its protection pipeline and primary user-facing tool. It rewrites DEX directly and handles DEX files, binary AndroidManifest.xml, resources.arsc, and ZIP entries inside APKs. It does not decompile applications to Java and rebuild them.

BirchDex supplies the parser/writer/builder, instruction and CFG models, type/liveness analysis, verification, linking, and partitioning infrastructure. BirchGuardLib adds configuration, transformations, lowering, cross-DEX renaming, resources, and reporting. BirchGuard is the transformation CLI; Birch is the low-level diagnostic CLI; BirchLinkageAudit performs read-only linkage audits. BirchGuardGUI provides the desktop interface.

Implemented families include renaming, constrained structural transformations, type-domain-aware control-flow flattening, opaque predicates, string/constant transformations, generated code, and resource transformations. Eligibility depends on supported instructions and provable safety contracts, not merely on a pass being enabled.

This is not an Android build system, AAB/JAR converter, native-code protector, general bytecode VM, or encrypted application packer. Names such as `crypto`, `cross_process`, `encrypted_paths`, and `array_virtualization` do not establish standardized cryptography, a separate process, a complete loader, or a VM. Consult [technique_catalog.cpp](src/birch/guard/technique_catalog.cpp) and the generated technique report for actual implementations.

### 2. How it works

#### Parsing, analysis, lowering, and verification

The pipeline loads the APK container, manifest, resources, and DEX files; applies scope and keep rules; and constructs type, inheritance, reference, and CFG information. Model transformations may create helpers before lowering into DEX instructions. Global rename planning updates cross-DEX references and supported manifest/resource references. ID remapping, layout, optional multidex partitioning, structural/type verification, code budgets, linkage checks, and legacy loading checks precede output.

`android_dex` is optional framework metadata for external inheritance/override resolution, never application code copied into the output. Supply a framework DEX appropriate to the target Android API. Missing or mismatched metadata limits resolution and rename safety.

#### Renaming and runtime contracts

Class, method, field, and package renaming share a global plan and reference closure. The planner conservatively handles framework overrides, package access, native/JNI, and recognized reflection contracts. Dynamically assembled names, serialization, plugins, and external integrations may still need explicit keep rules.

Scope patterns are DEX descriptors, for example `Lcom/example/**;`. A matching keep rule takes precedence over protect. Protect flags `allow_renaming`, `allow_code_transforms`, and `include_members` restrict eligible work; any matching protect rule denying a flag blocks that operation. Generated helper namespaces receive special scope treatment and can participate in subsequent protection.

#### Control-flow flattening and size safety

CFG, register type frames, and liveness analysis establish compatible type domains. Multi-level keyed dispatchers, encoded states/selectors, joint tokens, and runtime barriers replace eligible transitions. Unknown/uninitialized values and exception entries cannot be merged indiscriminately. Dead graphs use encoded edges, decoder islands, and sharded switches rather than only empty branches.

ConstantProgramOutliner, LinearRegionOutliner, and CfgRegionPlanner / CfgRegionOutliner extract safe regions under entry, continuation, type, live-in/live-out, exception, and monitor contracts. They do not split `invoke/move-result` or arbitrarily move handlers/monitor operations across try boundaries. Locks remain in the caller; unprovable cases are rejected.

CffCodeBudget counts business code, transitions, dead graphs, payloads, and alignment before emission, then checks actual size. On dedicated budget failures, CffPartitionPlanner refines extraction/partitioning from the pre-materialization source and reruns the pipeline with bounded retries. It does not silently lower intensity, remove dead states, or change the `seed` to obtain success.

The highest-strength policy includes 1024 dead states and an internal **16000-code-unit** ceiling. A DEX code unit is 16 bits; a user setting of 65000 does not disable that stricter ceiling. Full CFF emits `const-string/jumbo` before fixing layout, so later string-ID reordering cannot unexpectedly widen those loads; the real size is budgeted immediately.

OutputCodeBudget independently checks final serialized code-item sizes after renaming/partitioning. It recovers original owners through the rename map for scope checks and rejects remaining overflow. It does not secretly repartition at the output gate.

#### Strings, constants, and resources

Strings use a custom reversible UTF-16 transformation: four XOR/add base modes and eight per-character mixing rounds, with generated inverse runtime code. **This is not AES/ChaCha or cryptographic confidentiality: the decoder and keys ship with the application.** Constant programs, typed barriers, boolean arithmetic, constrained array/enum transformations, and metadata noise operate only at supported sites.

Resource file renaming uses collision-checked 16-token Unicode basenames, synchronizes ZIP and ARSC paths, and preserves suffixes, `.9.png`, and entry order. Eligible resource package key-pool names may become BirchGuard; resource IDs, type names, and user-visible text are not intentionally changed. Name lookup, `getIdentifier`, reflection, native code, overlays, and literal paths can trigger conservative preservation, with reasons recorded in the report.

#### Randomization and replay

The base `seed` is not necessarily the effective `seed`. Enabled build-parameter randomization mixes configuration; non-reproducible mode also adds runtime entropy. To replay recorded effective parameters, set root `"effective_seed": "16919314818285478265"` and retain the original input, configuration, framework, and engine version. Remove the override for normal randomized builds.

Root/pass seeds accept decimal `uint64` strings. Values above `9007199254740991` must be strings to avoid JSON number precision loss. `target_analysis_cost_weeks` is a policy heuristic, not a promise about actual reverse-engineering effort.

### 3. Source and build

Public headers live in `include/birch/`; implementation is split across `src/birch/dex/`, `guard/`, `io/`, and `utils/`. CLI and GUI code lives in `tools/`; configurations in `configs/`; synthetic regression sources in `tests/`; vendored GUI dependencies in `ImGUI/`; dependency notices in `licenses/` and the vendor directories.

Requirements: **CMake 3.22+**, a C++20 compiler, and zlib development files. The GUI additionally needs a C compiler, threads, and a desktop OpenGL development environment. Dear ImGui 1.93.0 and GLFW 3.4 are vendored; missing dependencies are not downloaded automatically.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBIRCH_BUILD_GUI=ON -DBIRCH_BUILD_TESTS=ON
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure -j 3
```

Use a terminal with the compiler, Ninja, and zlib configured. Set `ZLIB_ROOT`, or `ZLIB_INCLUDE_DIR` plus the full `ZLIB_LIBRARY` path, when discovery fails. The MinGW fallback only uses development files that actually exist. Compiler runtime DLLs must be discoverable when running Windows executables.

For Visual Studio, omit `-G Ninja`, build with `--config Release`, and test with `-C Release`; independently validate that toolchain. Linux GUI builds require development packages for the enabled GLFW X11/Wayland backends and OpenGL. Add `-DGLFW_BUILD_WAYLAND=OFF` if Wayland is not needed. macOS requires its development tools and OpenGL 3.2 core support. Windows is the locally exercised platform; source support is not a claim of tested Linux/macOS releases.

For CLI-only builds, configure a separate directory with `-DBIRCH_BUILD_GUI=OFF`. Tests can be disabled with `-DBIRCH_BUILD_TESTS=OFF`. Single-configuration CLI outputs are in `build/`, the GUI in `build/tools/gui/`; multi-configuration generators add configuration subdirectories.

BirchDex and BirchGuardLib can be consumed as in-tree static CMake targets. A stable ABI and complete installed `find_package(Birch)` interface are not provided yet.

```sh
cmake --install build --prefix install
cpack --config build/CPackConfig.cmake -G ZIP -B dist
```

For multi-configuration builds, add `--config Release` to install and `-C Release` to CPack. Installation includes CLI tools, the enabled GUI, core static libraries, public headers, configs, and notices. The CPack ZIP contains installed artifacts, not a complete source archive; compiler/zlib runtimes are not bundled automatically. Check deployment on a clean machine. Historical application-sample packaging scripts are not part of this workflow.

Application/framework binaries, outputs, mapping, signing keys, old version notes, and build artifacts should not be committed. `.gitignore` excludes these and unused vendor examples/backends; it neither physically deletes files nor untracks existing files. Required dependency licenses must remain, even when written in Markdown.

### 4. Configuration and CLI

Start with `BirchGuard --list-passes`. [rename_only.json](configs/rename_only.json) focuses on renaming; [resource_only.json](configs/resource_only.json) focuses on APK resources; [release_full.json](configs/release_full.json) is a high-growth, high-strength research profile, not a universally safe production default.

Unspecified passes inherit engine defaults: `_only` filenames do not automatically disable every other pass. Explicitly disable unwanted passes for strict allowlisting. Unknown keys, unknown pass IDs, and invalid parameters are rejected.

Replace `Lcom/example/**;` with your application descriptor scope; configure keep rules, framework metadata, and a private mapping path. Paths inside JSON are resolved relative to the **process working directory**, not the JSON directory. No application/framework fixture is required by the generic configs.

From the repository root on Windows PowerShell:

```powershell
.\build\BirchGuard.exe --list-passes
.\build\BirchGuard.exe --config configs/rename_only.json --inspect-apk input.apk
.\build\BirchGuard.exe --config configs/release_full.json --transform-apk input.apk output-unsigned.apk
.\build\BirchGuard.exe --config my-dex.json --transform-dex input.dex output.dex
.\build\Birch.exe --help
.\build\Birch.exe input.dex --verify
.\build\BirchLinkageAudit.exe input.apk
```

Use ./build/BirchGuard etc. on Unix-like systems. Supply your own authorized input. For standalone DEX, disable `resources.rename_files`, `resources.rename_names`, and both `resources.file_rename` / `resources.name_rename` passes. The GUI rejects incompatible resource settings.

Diagnostics include `Birch input.dex --map`, `--scan-cfg`, `--verify`, or `--audit-cff`; `Birch --partition <directory>`; and `Birch --inspect-apk <APK>`. Linkage audit syntax is `BirchLinkageAudit <APK|DEX> [android.dex] [--verbose]`. `BirchGuard --config <JSON> --prepare-fake-dex <output.dex>` generates research input, not an installable application.

Success returns 0, bad arguments 2, and parsing/transformation/verification failures 1. The Windows CLI uses narrow argv and may mishandle Unicode under some system code pages; use ASCII paths or the GUI when necessary.

Transformation writes the APK/DEX, `<output>.techniques.txt`, and optionally the configured mapping. Reports record effective `seed`, actual implementation, recorded application counts, and compatibility warnings. Zero counts or `not instrumented` are not proof of applied protection. Mapping and reports may expose name correspondence and build parameters; keep them private.

Input, output, mapping, and report paths must not overlap, including hard-link aliases. The CLI can replace existing output, so back it up; the GUI requests replacement confirmation.

### 5. GUI and signing

`build/tools/gui/BirchGuardGUI` is an English-language desktop application with an iOS-inspired visual style, not an iOS app. It supports path entry/drop, JSON import, scope/framework/mapping settings, pass filtering, and intensity controls. Applying Balanced/Strong/Maximum presets re-enables compatible passes. Debug-local noise and debug-info removal are mutually exclusive.

Jobs capture a configuration snapshot and run on `std::jthread`. A mutex-protected progress queue is capped at 2000 entries; workers never call ImGui. Settings are locked during work. Disabling live logs does not disable verification. Cancellation/resume is not implemented; closing is deferred during a running job, and long stages have no reliable percentage estimate.

With working desktop OpenGL, `BirchGuardGUI --smoke-test` and `--screenshot gui.png` perform basic hidden-window rendering checks, not full interaction or high-DPI acceptance tests.

APK outputs are **unsigned**, with stale signatures removed. Built-in signing is unavailable and enabling it errors. Use external Android SDK zipalign/apksigner tools and an authorized signing key, then verify the signature. Never commit keys or passwords. Changed certificates may break updates, integrity checks, or integrations. Validate installation, startup, business flows, resources, exceptions, and performance on target devices after signing.

### 6. Tests and known limitations

Retained regression sources construct synthetic inputs at runtime instead of requiring third-party APK/DEX/framework fixtures. Generated APKs are format/pipeline inputs, not installable applications. Assertions remain enabled for Release tests. Test interpreters implement a limited instruction/API oracle, not a complete Android runtime.

```sh
ctest --test-dir build --output-on-failure
ctest --test-dir build -L cff-budget --output-on-failure
ctest --test-dir build -LE extended --output-on-failure -j 3
ctest --test-dir build -L extended --output-on-failure
```

`cff-budget` exercises size, type/liveness, region, exception, and monitor contracts. `extended` currently selects the slower linear-region outliner regression. Full CTest includes both.

Known limitations:

- Static checks do not prove ART/device compatibility; there is no all-APK or all-Android-version guarantee.
- Dynamic reflection, JNI, serialization, plugins, resource-name lookup, and application self-checks can still break. Explicit keep rules and application acceptance tests remain necessary.
- High-strength CFF, helpers, and dead graphs increase size, call depth, build cost, and runtime overhead, and may trigger explicit budget rejection. No universal performance benchmark or protection score is established.
- Reversible string transformations and opaque/dead code can be analyzed or simplified; they are not cryptographic security boundaries.
- Malformed-input, fuzzing, and sanitizer coverage need expansion. The local MinGW toolchain lacks usable ASan/UBSan runtimes; sanitizer success is not claimed.
- Linux/macOS, other compiler combinations, high-DPI interaction, CLI Unicode paths, cancellation/resume, and transactional output need further validation or development.
- Built-in APK signing, SDK/framework downloads, stable ABI, and automatic deployment dependency collection are not provided.

Only process software you own or are authorized to transform. Do not upload third-party applications, credentials, private business logic, or personal data in issues.

### 7. Roadmap

Planned directions, not implemented features or delivery promises:

- ART/emulator/device regression matrices across Android APIs.
- Linux/macOS/multi-compiler CI, ASan/UBSan, static analysis, and parser fuzzing.
- More portable synthetic inputs and semantic exception/monitor regressions.
- Better diagnostics and keep validation for reflection, JNI, serialization, and named resources.
- Reproducible size, startup/runtime, and build-time benchmarks.
- GUI cancellation, recovery, failure diagnostics, and transactional output.
- Stable public APIs, exported CMake targets, presets, and cross-platform packaging.

### 8. Contributions welcome

Bug reports, documentation, tests, and PRs are welcome. Discuss substantial changes in an issue first. Keep each PR focused; explain semantics, safety contracts, and size/performance impact. Add a public minimal synthetic reproducer and regression, include platform/compiler/configuration/effective `seed`, and redact private paths, mapping, logs, and names.

Run relevant tests and full CTest; run `cff-budget` for CFF/partition changes. Do not claim full success after skipping slow tests. State untested platforms/device behavior honestly and include sanitizer/static-analysis results when applicable and available. Preserve dependency notices; do not add application samples, credentials, build outputs, or version-by-version notes.

### 9. Acknowledgments and licensing status

Thanks to Dear ImGui (Omar Cornut and contributors; MIT, [ImGui license](ImGUI/imgui-1.93.0/LICENSE.txt)), GLFW (Marcus Geelnard, Camilla Löwy and contributors; zlib/libpng-style license, [GLFW license](ImGUI/glfw-3.4/LICENSE.md)), and zlib (Jean-loup Gailly, Mark Adler and contributors; ZIP/PNG support, notice in [zlib notice](licenses/ZLIB.txt)). The linked zlib version is supplied by the toolchain. Thanks also to CMake, compiler authors, Android format documentation, and the wider open tooling ecosystem.

**The owner has not yet selected a project-level open-source license; there is currently no project LICENSE. Public source visibility does not grant usage, modification, or redistribution rights.** Add explicit project licensing/copyright terms before announcing an open-source release or accepting and merging external contributions. Dependency terms remain applicable independently; their notices must not be removed with obsolete documentation.
