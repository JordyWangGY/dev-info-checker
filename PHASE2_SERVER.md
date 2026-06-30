# 阶段二（服务端权威裁决）执行设计与现状对账

> **本文定位**：`ARCHITECTURE.md` §6/§8/§12.2 已给出阶段二的总体设计（attestation 流程、`:server` 组件、2.0–2.4 路线图）。本文**不重复**，只做两件事：
> 1. **现状对账**——把原设计与「**当前代码实际长什么样**」对齐，点出必须先补的缺口；
> 2. **可执行的批次推进**——每批给输入/输出/验收，按性价比与依赖排序。
>
> 本文是**设计文档**，不含服务端实现代码；服务端属独立构建目标 `:server`（**尚不存在**），不在本仓（Android 客户端）范围。端侧需要的改造在第 5 节单列（设计，未实现）。

---

## 1. 原则回顾

- **端侧出证据，服务端做信任锚 + 数据规模。**
- **客户端那份 `RiskReport` 是明文、可伪造**——服务端只把端侧信号当「参考」，以**验过签的硬件令牌**为信任锚，最终回一张**服务端签名的 Decision JWT**（业务后端独立验签，无需信任客户端）。
- 详见 `ARCHITECTURE.md` §0、§5.3。

---

## 2. 现状对账（**关键**：原设计 vs 当前实现）

| 能力 | ARCHITECTURE 设计假设 | 当前实际实现 | 差距 |
|---|---|---|---|
| nonce 防重放 | `/v1/nonce` 服务端下发、单次、TTL，贯穿 PI/attestation | `AttestDetector` 用**本地** `SecureRandom` challenge 当 nonce | 🔴 **未服务端化**——防重放/中继实际为空 |
| Play Integrity 令牌 | 上报令牌，服务端 `decodeIntegrityToken` | `PlayIntegrity` 拿到了令牌，但 `AttestDetector` 只存了 **`token_len`**，**令牌原文被丢弃**；`RiskReport` 无字段承载 | 🔴 **令牌没上传**——服务端无从解码 |
| Key Attestation 证书链 | 导出 X.509 链交服务端验链到 Google 硬件根 CA | `KeyAttestation.attest()` **只返回解析后的枚举值**（securityLevel/bootState…），**原始证书链未导出、未序列化** | 🔴 **链没上传**——服务端无法验签 |
| 证据上报传输 | `AttestApi` + EvidenceBundle 签名 + `/v1/attest` | **无任何传输层**——`RiskReport` 仅本地生成/`adb export` | 🔴 **未建** |
| Decision JWT 回包 | 服务端签发，`RiskReport.decisionJwt` 回填 | 字段已留(`decisionJwt: String? = null`)，**永远为 null** | 🟡 字段在、链路无 |
| 服务端组件 | `NonceService`/`PlayIntegrityVerifier`/`KeyAttestationVerifier`/`SignalCrossChecker`/`RiskScorer`/`DecisionSigner` | **`:server` 模块已建**（纯 JVM，复用 `:protocol`，零新依赖）：NonceService + KeyAttestationVerifier + (Stub)PlayIntegrityVerifier + AuthoritativeScorer + DecisionSigner(ES256) + AttestService + JDK HttpServer 演示端点；已单测 + HttpServer 实测 | 🟡 批次一引擎已建；Google 根固定 / PI 真解码 / 真机链验证待真凭证与样本 |
| 端侧新增信号 | （架构成文时未有） | 新增 `ecosystem.*`、`filetime.*`、`attest.play_integrity.env`、GMS 签名采集(`vending_sig`/`gms_sig`) | 🟡 服务端交叉校验需把这些纳入 |

> **一句话现状**：端侧已能产出本地 `RiskReport`，但**承载信任锚的两样东西（PI 令牌原文、attestation 证书链）当前根本没被传出去**，且 nonce 未服务端化。所以阶段二的第一要务不是写复杂规则，而是**先把信任锚的数据通路打通**。

---

## 3. 批次推进（映射 ARCHITECTURE §12.2 的 2.0–2.4）

### 批次一 · 信任锚 MVP（最高性价比，**不需要大数据**）

把端侧「采集了却没生效」的最强信号变成「可执行的权威裁决」。

| 子项 | 输入 | 输出 | 验收 |
|---|---|---|---|
| **2.0a 端侧补数据通路**（见 §5） | — | PI 令牌原文 + attestation 证书链(Base64 DER) + server nonce 进入上报包 | 上报包里能取到原始令牌与完整证书链 |
| **2.1 `NonceService` + `/v1/attest`** | 设备请求 | 单次/TTL nonce；接收 EvidenceBundle | nonce 重放被拒；过期被拒 |
| **2.2a `PlayIntegrityVerifier`** | PI 令牌 + nonce | `deviceRecognitionVerdict`(含 `MEETS_VIRTUAL_INTEGRITY`)、`appRecognitionVerdict`、`accountDetails` | 校验 nonce/packageName/证书摘要/timestamp 新鲜度/cloudProjectNumber 通过；模拟器令牌被判 virtual |
| **2.2b `KeyAttestationVerifier`** | X.509 链 + nonce | 验链到 **Google 硬件根 CA** + 查吊销；权威读 `verifiedBootState`/`securityLevel`/`rootOfTrust` | challenge==nonce；链可信；解锁/SOFTWARE 被识别 |
| **2.2c GMS 签名比对** | `vending_sig`/`gms_sig` | 是否==Google 官方证书 | microG/假 GMS（端侧采到的 `08BA6D…` 类非官方证书）被判伪 |
| **2.3 `DecisionSigner`** | 上述结论 | 服务端私钥签名的 **Decision JWT** | 业务后端用公钥验签可信任；与设备实例密钥绑定 |

> 完成批次一：`attest.play_integrity.virtual`、`attest.key.verified_boot_fail`、`attest.key.not_hardware` 三个**硬件阻断点从「采集」转为「权威生效」**，且端侧伪造报告骗不过服务端。

### 批次二 · 一致性 / 自洽（单记录即可，**轻量数据**）

- **`SignalCrossChecker`（自述 vs 硬件真相）**：客户端自报机型/属性 与 PI/attestation 的硬件真相对撞打假。
- **机型自洽**：声称机型 ↔ Widevine L 级 ↔ SoC ↔ `ecosystem.inventory` 生态包 ↔ RAM/屏幕/ABI 互相矛盾即可疑。
- **误报复核（重要）**：用 `fp.attributes` 的 SIM 国家/地区把端侧 FP-prone 信号（`ecosystem.no_gms`、`filetime.*`、`attest.play_integrity.env` 的 `PLAY_SERVICES_NOT_FOUND` 等）在服务端**降噪**——去谷歌/国行/无账号真机洗白。这是这些信号的正确归宿（见 `DETECTION_COVERAGE.md` §A/§E）。

### 批次三 · 图谱 / velocity / 网络（**需数据规模**，对付肉鸡/团伙）

- `FingerprintStore`：设备去重、新设备频次、群体基线(rarity)。
- 设备图谱（共享指纹/账号/资金）、velocity（一机多号、超距同步）、TLS/JA3 + TCP/IP 栈指纹 vs 自报机型冲突、住宅代理 IP 情报。
- 这层只有聚合端可见，是 `DETECTION_COVERAGE.md` §B 🔴 档的唯一解。

---

## 4. 客户端 ↔ 服务端契约

**复用 `:protocol` 模块**（客户端与服务端共享同一套 `Signal`/`Category`/`Severity`/`Scoring` 权重，保证两端一致；权重热更放服务端，免客户端发版）。

**请求（设备 → `/v1/attest`，EvidenceBundle）**：
- `nonce`：来自 `/v1/nonce`（服务端单次/TTL）
- `playIntegrityToken`：PI 令牌**原文**（当前缺，见 §5）
- `keyAttestationChain`：X.509 证书链 Base64 DER 列表（当前缺，见 §5）
- `localReport`：本地 `RiskReport`（signals/证据，**仅作参考**）
- `instanceSignature`：用 app 实例硬件密钥对 bundle 签名（绑定真实硬件，抗重打包/多开/中继）

**响应（服务端 → 设备 / 业务后端，Decision JWT claims）**：
- 权威 `verdict` + `score`（服务端 `RiskScorer` 算）
- 关键判定：deviceIntegrity / verifiedBoot / gmsAuthentic 等
- `nonce`、`exp`、绑定的设备实例公钥指纹
- 业务后端用服务端公钥**独立验签**即可信任，无需信任客户端。

> `RiskReport.decisionJwt` 即此 JWT 的回填位（现为 null）。

---

## 5. 端侧为阶段二必须先补的改造（**在本仓，设计，未实现**）

这些是批次一 2.0a 的内容，属本仓客户端范围。**本文只描述，不在此实现**：

1. **导出 attestation 证书链**：`KeyAttestation.Result` 增加原始链字段（Base64 DER 列表），`attest()` 不再只返回解析值。
2. **保留并上报 PI 令牌原文**：`AttestDetector` 当前只存 `token_len`，需把 `pi.token` 纳入上报包（注意：令牌不进明文日志/`RiskReport.signals` evidence，单独走加密上报）。
3. **nonce 服务端化**：新增取 nonce 的接口（`/v1/nonce`），替换 `AttestDetector` 里本地 `SecureRandom` challenge；nonce 贯穿 PI `requestHash` / attestation `attestationChallenge` / bundle 签名。
4. **上报传输层**：`AttestApi`（OkHttp）+ EvidenceBundle 组装与实例密钥签名 + `DecisionJwt` 回包解析回填 `RiskReport.decisionJwt`。
5. **gating 细化**（可选）：区分「未配 `cloudProjectNumber`」与「环境报错」，见 `DETECTION_COVERAGE.md` §E。

---

## 6. 权威评分 vs 端侧本地分

- **权威分在服务端算**（`RiskScorer`，权重热更）。
- 端侧 `LocalRiskScorer` 只算一个**降级 / 灰度 / 埋点用的预估分**，结论「可参考、不可信」（`ARCHITECTURE.md` §5.2/§12.1）。
- 两端共用 `:protocol` 权重，避免口径漂移。

---

## 7. 隐私合规

遵循 `ARCHITECTURE.md` §10：最小采集、本地优先（能本地判定的不上传原文）、透明告知、数据保留期与脱敏。令牌/证据包仅用于风控判定与审计。

---

## 8. 现状与验证缺口（如实记录）

- **批次一验证引擎已建**（`:server`）：NonceService / KeyAttestationVerifier（含 DER 解析）/ Stub PlayIntegrityVerifier / AuthoritativeScorer / DecisionSigner(ES256) / AttestService / JDK HttpServer 演示端点。`:server:test` 全通过；HttpServer 实测：`/v1/nonce` 下发 → 客户端自称 GENUINE 却带 NATIVE frida 阻断信号 → 服务端**重算判 COMPROMISED/100** 并签发可验签 Decision JWT → 同一 nonce 重放被拒。
- **批次二已起步**：`SignalCrossChecker`（自洽性打假，融合进 `AuthoritativeScorer`）——说谎客户端（带阻断信号却自报 GENUINE）、自报分 vs 重算分不符、Widevine L1 vs SOFTWARE TEE、声称主流 ARM 机型却 x86 ABI、GMS 签名不符。已单测 + HttpServer 实测（声称 samsung 却 x86 → 服务端从 GENUINE/0 升到 LOW_RISK/35）。**不依赖真机/凭证。** 机型自洽其余规则、用 SIM 国家做 FP 复核待续。
- **批次三**：未开工。
- **仍依赖真凭证 / 真机样本**（已在代码标 TODO）：① Google 硬件 attestation 根证书**固定**（`trustedRootSha256` 当前为空 → rootTrusted 恒 false）；② Play Integrity **真解码**（需 Google Cloud 项目 + 服务账号，现为 Stub）；③ **真实证书链**端到端验签（当前单测覆盖 DER 解析 + 链遍历逻辑，未用真机链跑通）。
- 端侧目前**只在 redroid 容器验证**；`attest.play_integrity.env` 未现场触发（sample 未配 `cloudProjectNumber`）。

---

## 9. 不在本文范围 / 未决项

- 服务端选型细节（Ktor 已在 `ARCHITECTURE.md` §11 定）、部署、密钥管理（HSM/KMS）、Decision JWT 算法与轮换。
- `appAccessRiskVerdict`（PI 较新字段，查屏幕共享/无障碍滥用）是否启用——需服务端解码 + Play 控制台配置，见 `DETECTION_COVERAGE.md` §E。
- Play Integrity Classic vs Standard 的最终取舍（取决于调用频率），见 `DETECTION_COVERAGE.md` §E。
