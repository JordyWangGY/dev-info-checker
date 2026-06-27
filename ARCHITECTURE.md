# DevCheck — Android 环境可信检测架构

> 目标：为宿主 App 提供一套**可被集成的环境完整性检测能力**，判断「当前运行环境是否真实可信」，
> 用于反作弊 / 反欺诈 / 风控前置。本项目从 0 自研，覆盖国内（无 GMS）与海外（Google Play）双场景。
> **目标平台：Android 12+（API 31+）。**

---

## 0. 一句话设计哲学

> **代码运行在攻击者的机器上。** 任何纯客户端的布尔判断（`isEmulator() → true/false`）都能被
> hook、patch、重打包绕过。所以本架构不做「一个检测函数」，而是做四件事：
>
> 1. **多源弱信号采集**（raise the bar，单点绕过不致命）
> 2. **硬件背书锚点**（Play Integrity / Key Attestation，攻击者无法在普通设备上伪造）
> 3. **服务端风险评分与裁决**（客户端只采集证据，结论在服务端算）
> 4. **检测代码自身的抗篡改 / 自保护**（让绕过的成本高于收益）

---

## 1. 威胁模型（我们要对抗什么）

| 类别 | 攻击手段 | 典型工具 |
|---|---|---|
| 模拟器 | 在 PC 上模拟 Android 运行 App | BlueStacks / NoxPlayer / LDPlayer / MuMu / 雷电 / Genymotion / Android Studio AVD |
| Root | 获取超级用户权限以改写系统 | Magisk / SuperSU / KernelSU |
| Hook 框架 | 运行时篡改方法返回值、内存 | Xposed / EdXposed / LSPosed / Frida / Substrate / Riru / Zygisk |
| 多开 / 虚拟空间 | 在一个宿主里跑多个 App 实例 | VirtualApp / 平行空间 / 双开助手 / 分身 |
| 调试 / 动态分析 | attach 调试器、ptrace、抓内存 | gdb/lldb / IDA / Frida / ADB |
| 重打包 / 篡改 | 改包后重签名分发 | apktool / 二次打包 |
| 网络伪装 | 改 IP / 抓包 / 中间人 | VPN / 代理 / mitmproxy |
| 设备伪造 | 篡改设备指纹、机型、IMEI | 改机工具 / 框架插件 |

> **原则**：我们不追求「100% 抓到」（不可能），而是追求「**让伪造一个看起来真实的环境，
> 成本高到攻击者放弃**」，并把残余风险量化成分数交给业务侧决策。

---

## 2. 总体架构

```
┌──────────────────────────────────────────────────────────────────────┐
│                          宿主 App (你的业务 App)                          │
│   val report = DevCheck.evaluate()  // 一行调用                           │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │ 集成 AAR
┌───────────────────────────────▼──────────────────────────────────────┐
│                        :sdk  (Android Library, AAR)                     │
│                                                                        │
│  ┌── Public API ──────────────────────────────────────────────────┐  │
│  │  DevCheck.init() / evaluate() / RiskReport / DevCheckConfig      │  │
│  └─────────────────────────────────┬──────────────────────────────┘  │
│  ┌── Orchestration / Risk Engine ──▼──────────────────────────────┐  │
│  │  Orchestrator(并发+超时) · LocalRiskScorer · EvidenceCollector   │  │
│  └───────┬───────────────────────────────────────────┬────────────┘  │
│  ┌───────▼── Detectors (可插拔, 每个产出 Signal[]) ─────▼───────────┐  │
│  │ Emulator · Root · Hook · Debug · VirtualSpace · Tamper · Network │  │
│  │ DeviceFingerprint · PlayIntegrity · KeyAttestation              │  │
│  └───────┬─────────────────────────────────────────────────────────┘  │
│  ┌───────▼── Native Core (C++/JNI, 抗 Java 层 hook) ────────────────┐  │
│  │ /proc 解析 · 直接 syscall · 反 ptrace · inline-hook 检测 · 自校验  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│  ┌── Attestation & Transport ──────────────────────────────────────┐  │
│  │  AttestationBuilder(签名证据包) · AttestApi(nonce→attest)         │  │
│  └─────────────────────────────────┬──────────────────────────────┘  │
└────────────────────────────────────┼─────────────────────────────────┘
                                      │ HTTPS (证据包 + 硬件令牌, 带 nonce)
┌─────────────────────────────────────▼─────────────────────────────────┐
│                       :server (Ktor 风控引擎, 可信侧)                     │
│  /v1/nonce  → 下发一次性挑战值                                            │
│  /v1/attest → PlayIntegrityVerifier · KeyAttestationVerifier            │
│              · SignalCrossChecker(客户端自述 vs 硬件真相)                  │
│              · RiskScorer(权威评分) · DecisionSigner(签名裁决JWT)         │
└────────────────────────────────────────────────────────────────────────┘
                                      │
                          宿主 App 的业务后端校验 Decision JWT → 放行/拦截/降级
```

### 双通道硬件背书（核心差异化）

| 场景 | 硬件锚点 | 说明 |
|---|---|---|
| 有 GMS（海外 / Google Play） | **Play Integrity API** | 单项最强信号；令牌在**服务端**解码校验 |
| 无 GMS（国内） | **Android Key Attestation** | 系统级、不依赖 Google；证书链验签到 Google 硬件根 CA，拿到 verified boot / 锁机状态 |
| 二者皆可 | 两个都采，取强 | 自动探测 GMS，缺失则降级 |

> 关键认知：模拟器/改机无法产出一条能验签到 **Google 硬件根 CA** 的 Key Attestation 证书链，
> 也无法让 Play Integrity 返回 `MEETS_STRONG_INTEGRITY`。硬件锚点是整套体系里攻击者**最难伪造**的一环，
> 其余所有 Java/Native 信号都是它的补充与交叉印证。

---

## 3. 模块划分（Gradle 多模块）

```
dev-info-checker/
├── ARCHITECTURE.md          ← 本文档
├── settings.gradle.kts
├── build.gradle.kts         ← 根
├── gradle/libs.versions.toml← 版本目录(单一事实源)
├── protocol/                ← 纯 Kotlin/JVM，客户端与服务端共享的 DTO + 信号目录 + 评分权重
│   └── com/devcheck/protocol/  (Signal, Category, Severity, Verdict, EvidenceBundle,
│                                RiskReport, Decision, AttestRequest/Response, SignalCatalog)
├── sdk/                     ← Android Library (AAR) —— 交付物
│   └── src/main/
│       ├── kotlin/com/devcheck/
│       │   ├── DevCheck.kt / DevCheckConfig.kt          (Public API)
│       │   ├── core/      (Orchestrator, LocalRiskScorer, EvidenceCollector, ...)
│       │   ├── detector/  (Detector 接口 + 各 Detector 实现)
│       │   ├── attest/    (PlayIntegrityClient, KeyAttestationClient)
│       │   ├── net/       (AttestApi, OkHttp)
│       │   └── nativebridge/ (NativeProbe JNI 封装)
│       ├── cpp/           (native core, CMakeLists.txt)
│       └── proguard/      (consumer-rules.pro 抗逆向规则随 AAR 下发)
├── sample/                 ← 示例 App：跑通并可视化所有信号
└── server/                 ← Ktor 风控引擎
```

> `protocol` 用纯 Kotlin/JVM 模块，被 `:sdk`（Android）与 `:server`（JVM）**同时依赖**，
> 保证信号 ID、DTO、评分权重三端一致，是单一事实源。

---

## 4. 检测能力矩阵

每个 Detector 产出 `List<Signal>`；标 ⚙️ 的关键判定在 **Native 层**做（直接 syscall，绕过 libc/Java hook）。

| Detector | 信号样例 (signal id) | 关键实现要点 | 抗绕过 |
|---|---|---|---|
| **Emulator** | `emulator.build_props` `emulator.no_sensors` `emulator.gpu_swiftshader` `emulator.qemu_files`⚙️ `emulator.cpu_x86_on_arm` | Build 指纹/机型黑名单、缺陷传感器、GPU renderer(SwiftShader/llvmpipe)、qemu 管道文件、基带/电话缺失、arch 异常 | 中 |
| **Root** | `root.su_binary`⚙️ `root.magisk`⚙️ `root.test_keys` `root.rw_system`⚙️ `root.dangerous_props` | su/busybox 路径(syscall faccessat)、Magisk 路径/包/zygisk、`Build.TAGS` test-keys、system 可写、`ro.debuggable`/`ro.secure` | 中 |
| **Hook** | `hook.xposed.classloader` `hook.xposed.stacktrace` `hook.frida.maps`⚙️ `hook.frida.port` `hook.frida.threads`⚙️ `hook.inline_hook`⚙️ | XposedBridge/ClassLoader、异常栈注入帧、`/proc/self/maps` 扫 frida/gum/lspd/substrate、frida 默认端口 27042、可疑线程名(gmain/gum-js-loop)、关键函数序言改写检测 | 高(native) |
| **Debug** | `debug.debugger`⚙️ `debug.tracerpid`⚙️ `debug.adb_enabled` `debug.debuggable_flag` | `Debug.isDebuggerConnected`、`/proc/self/status` TracerPid≠0、`Settings.Global ADB_ENABLED`、`FLAG_DEBUGGABLE`、反 `PTRACE_TRACEME` | 高(native) |
| **VirtualSpace** | `vspace.data_path` `vspace.maps_foreign_apk`⚙️ `vspace.dual_process` | data 目录路径异常、`/proc/self/maps` 含其它包 apk、进程/uid 冲突、宿主特征包名 | 中 |
| **Tamper** | `tamper.signature` `tamper.installer` `tamper.dex_crc` `tamper.so_integrity`⚙️ | 签名证书指纹比对(编译期内置)、安装来源(非应用商店)、dex/so 校验和、native 自校验 | 高 |
| **Network** | `network.vpn` `network.proxy` | `NetworkCapabilities TRANSPORT_VPN`/tun0、系统代理属性 | 低(仅参考) |
| **DeviceFingerprint** | `fp.stable_id` `fp.inconsistency` | 稳定设备 ID、机型/硬件字段自洽性校验；服务端做去重与频次 | — |
| **PlayIntegrity** | `attest.play_integrity.token` | 携带 server nonce 请求令牌；**不在客户端解码** | 极高 |
| **KeyAttestation** | `attest.key.cert_chain` | StrongBox 优先→TEE，challenge=nonce，导出证书链交服务端验签 | 极高 |

> **失败即风险（fail-closed）**：任一 Detector 抛异常 / 超时 / Native 库缺失，
> 不当作「通过」，而是产出一条 `MEDIUM~HIGH` 的 `*.detector_error` 信号——攻击者破坏检测器本身也会留痕。

---

## 5. 信号与评分模型

### 5.1 Signal（统一证据单元，定义在 protocol）

```kotlin
data class Signal(
  val id: String,             // "root.su_binary"，全局稳定命名空间
  val category: Category,     // ROOT/EMULATOR/HOOK/DEBUG/VSPACE/TAMPER/NETWORK/ATTEST/FINGERPRINT
  val severity: Severity,     // INFO < LOW < MEDIUM < HIGH < CRITICAL
  val confidence: Float,      // 0f..1f，单条证据可信度
  val source: Source,         // JAVA / NATIVE / HARDWARE
  val evidence: Map<String,String> // 原始证据，便于服务端复核与离线分析
)
```

### 5.2 分数与裁决

- 分值 `0..100`（0=干净）。按 `severity × confidence × category 权重` 加权求和并做饱和；同类多条做上限封顶，避免单类堆叠刷分。
- 裁决枚举与默认阈值（业务可调）：

| Verdict | score | 含义 |
|---|---|---|
| `GENUINE` | < 20 | 可信 |
| `LOW_RISK` | 20–40 | 轻度可疑 |
| `SUSPICIOUS` | 40–70 | 可疑，建议加验证（短信/人脸） |
| `HIGH_RISK` | 70–90 | 高危 |
| `COMPROMISED` | ≥ 90 | 判定环境不可信 |
| `UNKNOWN` | — | 未能评估（离线/超时） |

### 5.3 服务端交叉校验（本架构的「杀手锏」）

客户端自述信号**可被篡改**，所以服务端拿**硬件真相**反向打假：

- 硬件 Key Attestation 显示 `verifiedBootState != GREEN` 或 `deviceLocked=false`，但客户端自述 root 信号为空 → **客户端在撒谎/被致盲** → 大幅加权 + 直接拉到 `HIGH_RISK` 以上。
- Play Integrity 返回 `MEETS_VIRTUAL_INTEGRITY`（模拟器），但客户端自述非模拟器 → 同上。
- 硬件层缺少 `MEETS_DEVICE_INTEGRITY` → 硬性下限封底。

> **权威分在服务端算**，客户端只算一个用于离线/降级的 `LocalRiskScorer` 预估分。

---

## 6. Attestation 端到端流程（带 nonce 防重放）

```
宿主App        :sdk                          :server                 业务后端
  │  evaluate()  │                               │                      │
  ├─────────────►│  ① GET /v1/nonce ────────────►│  生成一次性 nonce      │
  │              │◄────────── nonce ─────────────┤  (绑定 TTL, 防重放)    │
  │              │  ② 并发跑 Detectors → Signal[] │                      │
  │              │  ③ PlayIntegrity(nonce) /      │                      │
  │              │     KeyAttestation(challenge=  │                      │
  │              │     nonce) → 硬件令牌           │                      │
  │              │  ④ 用 app 实例硬件密钥对         │                      │
  │              │     EvidenceBundle 签名         │                      │
  │              │  ⑤ POST /v1/attest ───────────►│  验 PlayIntegrity令牌  │
  │              │                               │  验 KeyAttest 证书链   │
  │              │                               │  交叉校验+权威评分      │
  │              │◄──── Decision JWT(签名) ───────┤  签发裁决             │
  │◄─ RiskReport(含Decision JWT) ─┤              │                      │
  │  携 Decision JWT 调用业务接口 ──────────────────────────────────────►│ 验JWT→放行/拦截
```

要点：
- **nonce 全程贯穿**（Play Integrity 的 `requestHash`、Key Attestation 的 `attestationChallenge`、bundle 签名），杜绝令牌重放与「真机代签、模拟器使用」的中继攻击。
- **令牌只在服务端解码校验**，客户端拿到的明文一律不可信。
- 最终产物是一张**服务端签名的 Decision JWT**，宿主 App 的业务后端独立验签即可信任，无需信任客户端。

---

## 7. 客户端 SDK API（最小可用、难误用）

```kotlin
// 初始化（Application.onCreate）
DevCheck.init(context, DevCheckConfig(
    serverBaseUrl = "https://risk.example.com",
    appAttestationCertSha256 = "<编译期内置的签名指纹>",
    playIntegrityCloudProjectNumber = 123456789L, // 有 GMS 时
    enabledDetectors = Detectors.ALL,
    perDetectorTimeoutMs = 800,
))

// 评估（挂起函数；也提供 callback 重载）
val report: RiskReport = DevCheck.evaluate()
when (report.verdict) {
    Verdict.GENUINE     -> proceed()
    Verdict.SUSPICIOUS  -> stepUpAuth()
    else                -> block()
}
report.decisionJwt   // 透传给业务后端做权威校验
report.signals       // 命中的证据，便于埋点/灰度
```

---

## 8. 服务端（:server, Ktor）

| 组件 | 职责 |
|---|---|
| `NonceService` | 下发/校验一次性挑战值（TTL + 单次消费） |
| `PlayIntegrityVerifier` | 调 Google Play Integrity API `decodeIntegrityToken`，读 `deviceIntegrity/appIntegrity/accountDetails` |
| `KeyAttestationVerifier` | 解析 X.509 链，验签到 Google 硬件根 CA，读 attestation 扩展(OID 1.3.6.1.4.1.11129.2.1.17)：安全级别(TEE/StrongBox)、verifiedBootState、deviceLocked、osPatchLevel；校验 challenge==nonce |
| `SignalCrossChecker` | 客户端自述信号 × 硬件真相，打假撒谎客户端 |
| `RiskScorer` | 权威评分（权重可热更，免客户端发版） |
| `DecisionSigner` | 用服务端私钥签发 Decision JWT |
| `FingerprintStore`（演进项） | 设备去重、新设备频次、关联风控 |

---

## 9. 自我保护与抗篡改

- **关键判定下沉 Native**：用 `syscall(SYS_faccessat/openat)` 直接读文件与 `/proc`，绕过 libc/Java 层 hook；检测关键函数序言被改写（inline hook）。
- **Native 自校验**：校验自身 `.so` text 段、校验 JNI 调用方包签名（编译期内置证书指纹）。
- **硬件根信任**：首启生成硬件支持的实例密钥，服务端用 attestation challenge 把它**绑定到真实硬件**；Decision JWT 与该密钥绑定，**重打包/多开/换机无法伪造**有效裁决。
- **混淆与字符串加密**：R8/ProGuard + 敏感字符串（su 路径、frida 特征）加密，consumer-rules 随 AAR 下发。
- **可热更**：信号权重、机型黑名单、阈值放服务端，免客户端频繁发版。

---

## 10. 隐私与合规（必须前置考虑）

- **最小采集**：默认不采 IMEI/MAC 等强 PII；设备指纹用可重置 ID 或服务端单向哈希。
- **透明告知**：在隐私政策声明「为反欺诈检测运行环境」，提供合规出口（如 GDPR/个保法）。
- **数据生命周期**：证据包仅用于风控判定与审计，设定保留期与脱敏。
- **本地优先**：能本地判定的不上传原始证据，降级模式可纯本地出 `RiskReport`（标 `UNKNOWN` 风险等级）。

---

## 11. 工程化与版本

| 项 | 选型 |
|---|---|
| 语言 | Kotlin 全栈 + C++(NDK) 原生核心 |
| minSdk / targetSdk / compileSdk | **31 / 35 / 35（仅 Android 12+）**；StrongBox / Key Attestation 在 12+ 更普及 |
| 构建 | Gradle KTS + Version Catalog；**JDK 17**（AGP 8.7） |
| 异步 | Kotlin Coroutines |
| 序列化 / 网络 | kotlinx.serialization + OkHttp |
| 硬件背书 | `com.google.android.play:integrity` + AndroidKeyStore Attestation |
| 服务端 | Ktor (Netty)，复用 `:protocol` |
| 混淆 | R8 + consumer ProGuard rules |

### 构建前置（已自动配置完成）
- **JDK 17**：复用系统已装 `/usr/lib/jvm/java-17-openjdk-amd64`；已在全局 `~/.gradle/gradle.properties` 写入 `org.gradle.java.home` 固定守护进程 JVM。
- **Gradle 8.11.1**：复用本机缓存发行版并生成 wrapper，`./gradlew` 开箱即用。
- **NDK 27 + CMake 3.22.1**：经 `sdkmanager` 安装（供阶段一 1.2 原生层；缺失时优雅降级，不阻塞编译）。
- 命令行构建：`JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 ./gradlew assembleDebug`。

---

## 12. 交付路线图（两阶段）

### 阶段一：纯客户端检测（当前阶段，可独立 demo）
产物：可集成的 **AAR + 示例 App**，全部检测在本地完成，输出本地 `RiskReport`。
> 注：纯客户端结论「**可参考、不可信**」——本地分用于灰度 / 埋点 / 离线降级，不作为最终风控依据（最终裁决在阶段二的服务端）。

- **1.0 工程骨架**：Gradle 多模块 + `:protocol`（DTO / 信号目录 / 评分权重）+ `:sdk` 公共 API + Orchestrator + LocalRiskScorer + 示例 App ✅
- **1.1 启发式检测全量**：Emulator / Root / Hook / Debug / VirtualSpace / Tamper / Network / Fingerprint（Kotlin 层）
- **1.2 Native 核心**：JNI + C++（`/proc` 解析、`syscall(faccessat/openat)`、反 ptrace、inline-hook 检测、`.so` 自校验）
- **1.3 硬件背书（客户端采集 + 本地解析）✅**：Key Attestation 证书链本地解析 verifiedBoot / 锁机 / 安全级别（→ #6/#7 阻断点生效）；Play Integrity 令牌采集（验签留待阶段二）
- **1.4 自保护 + 示例可视化 ✅**：inline-hook 检测 + `.so` 自校验（两个 NATIVE 阻断点）、检测特征 XOR 字符串混淆（`.so` 与 dex 均搜不到明文特征）、consumer-rules 混淆规则随 AAR 下发、示例可视化裁决/分类分/阻断点/信号明细

### 阶段二：接入服务端（权威裁决）
产物：**Ktor 风控引擎 + SDK 接入 nonce/attest 流程**，输出服务端签名 **Decision JWT**。

- **2.0** `:protocol` 扩展 attest 报文；SDK `AttestApi` + nonce 流程 + EvidenceBundle 签名（app 实例硬件密钥）
- **2.1** 服务端 `:server`：`NonceService` + `/v1/attest`
- **2.2** `PlayIntegrityVerifier`（服务端解码）+ `KeyAttestationVerifier`（验签到 Google 硬件根 CA）
- **2.3** `SignalCrossChecker`（自述 vs 硬件真相）+ 权威 `RiskScorer` + `DecisionSigner`（JWT）
- **2.4** 端到端联调 + 业务后端校验 JWT 示例

---

## 13. 阻断点（Blocking Points）与评分 —— 逐项清单

### 13.1 评分（打分）模型
- 公式：`score = min(100, Σ_类别 min(70, Σ(severityWeight × confidence)))`
- 权重：`INFO=0 · LOW=5 · MEDIUM=15 · HIGH=35 · CRITICAL=60`；单类封顶 **70**（防同类弱信号堆叠刷分）
- 阈值 → 裁决：`<20 GENUINE · <40 LOW_RISK · <70 SUSPICIOUS · <90 HIGH_RISK · ≥90 COMPROMISED`

### 13.2 阻断点（命中即 100% 不可信，强制 COMPROMISED）
**入选标准**（缺一不可）：① **dispositive**（合法真机上误报率≈0）；② **来源可信**（NATIVE 直接 syscall / HARDWARE 硬件背书）。
> ⚠️ 纯 **Java** 来源的同名信号**只计分、不阻断**——Java 层可被 hook 伪造，不足以支撑「100%」。
> ⚠️ 命中阻断点**不停止检测**：所有 detector 跑完，全部证据与全部阻断点都保留在报告 `blockingSignals` / `signals` 中。

| # | 信号 ID | 为何 100% | 来源 | 阶段 |
|---|---|---|---|---|
| 1 | `hook.frida.maps` | 本进程地址空间映射了 frida-agent/gum（原生读 /proc/self/maps 确认）；合法进程绝无 | NATIVE | 1.2 ✅ |
| 2 | `debug.tracerpid` | TracerPid≠0：调试器/Frida 已 ptrace attach（原生确认） | NATIVE | 1.2 ✅ |
| 3 | `emulator.qemu_pipe` | 存在 `/dev/qemu_pipe`、`/dev/socket/qemud`（原生 faccessat 确认）；仅模拟器具备 | NATIVE | 1.2 ✅ |
| 4 | `hook.inline_hook` | 关键 libc 函数序言被改写为 hook 跳板（原生确认 LDR/BR、jmp 等跳板形态） | NATIVE | ✅1.4 |
| 5 | `tamper.so_integrity` | 本 SDK `.so` 代码段「可写可执行」/ 被打补丁（原生确认） | NATIVE | ✅1.4 |
| 6 | `attest.key.verified_boot_fail` | 硬件 Key Attestation：verifiedBootState ≠ GREEN / deviceLocked=false | HARDWARE | ✅1.3 本地 / 2.0 |
| 7 | `attest.key.not_hardware` | 证书链无法回溯 Google 硬件根 CA，或安全级别=SOFTWARE（无真实 TEE） | HARDWARE | ✅1.3 本地 / 2.0 |
| 8 | `attest.play_integrity.virtual` | Play Integrity=MEETS_VIRTUAL_INTEGRITY 或缺 MEETS_DEVICE_INTEGRITY | HARDWARE | 2.0 |

> 单一事实源在代码 `protocol/.../Blockers.kt`（客户端与服务端共用）。✅ = 已实现并经 `ScoringTest` 单测覆盖。
```

