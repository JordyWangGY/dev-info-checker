# 检测能力覆盖与边界

> 本文把攻防推演中出现的检测点逐项归档，明确**哪些已在客户端实现、哪些必须放服务端、哪些客户端做不到/不可靠、哪些被明令排除**。
>
> 总原则：**客户端只能"采集证据 + 本地实锤(存在性/原生/硬件)"；一致性、关联、图谱、velocity、群体基线本质是"服务端 + 数据规模"能力。**
>
> 图例：✅ 客户端已实现　🟦 阶段二·服务端　⚠️ 客户端受限/不可靠　⛔ 用户明令排除

---

## A. ✅ 客户端已实现 / 本轮新增

| 能力 | 信号 ID | 说明 | 来源 |
|---|---|---|---|
| 模拟器 | `emulator.*` | Build 指纹/机型、QEMU 文件、x86 ABI、传感器缺失 | JAVA/NATIVE |
| **传感器伪造**（新） | `emulator.sensor_static` | 采样加速度计，零方差/恒定值=伪造（真机静置也有微抖动） | JAVA |
| **SELinux/安全上下文**（新） | `emulator.selinux_permissive` `emulator.selinux_context` `emulator.selinux_fs` `emulator.selinux_info` | 容器/云机最早露馅的一层：非 enforcing、selinuxfs 缺失、自身域非规范 `untrusted_app`(如 `unconfined`)。读取走 native syscall 抗 hook，**仅计分、无阻断点**（rooted 真机 setenforce 0 也会 permissive）。采集项喂服务端做机型/版本一致性复核 | JAVA(native 读) |
| **云手机/容器**（新） | `emulator.cloud_kernel` `cloud_disk` `cloud_pci` `cloud_input` `cloud_cgroup` `cloud_net` `cloud_no_battery` `cloud_soundcard` `cloud_info` | ARM-on-ARM 共享内核容器(redroid 类)——经典 x86/QEMU/clocksource 失效。查宿主内核串(Ubuntu/gcc)、virtio 磁盘、PCI 总线、QEMU 输入、systemd cgroup、只有 eth0、无电池、Intel 声卡等。读取走 native readText/File.list，**仅计分、无阻断点**（单条可被伪造，靠叠加+服务端一致性）。调研见 `CLOUDPHONE_DETECTION.md` | JAVA(native 读) |
| Root | `root.su_binary` `root.magisk` `root.test_keys` `root.rw_system` | su/Magisk 路径(混淆)、test-keys、system 可写 | JAVA/NATIVE |
| **KernelSU/APatch**（新） | `root.kernelsu` | `/data/adb/ksu`、`/data/adb/ap` 等内核级提权特征 + 包名 | JAVA/NATIVE |
| Hook | `hook.frida.*` `hook.xposed` `hook.substrate` `hook.inline_hook` | maps 扫描(原生)、frida 端口/线程、inline-hook 跳板 | NATIVE/JAVA |
| 调试 | `debug.*` | 调试器、TracerPid(原生)、ADB、debuggable | NATIVE/JAVA |
| **多开/沙盒**（增强） | `vspace.data_path` `vspace.process_name` `vspace.classloader` `vspace.maps_foreign_apk` | 进程名≠包名、沙盒类加载器/路径、他包 apk 映射 | JAVA |
| 篡改 | `tamper.signature` `tamper.installer` `tamper.so_integrity` | 签名比对、安装来源、.so 自校验(原生) | JAVA/NATIVE |
| **全面指纹**（增强） | `fp.attributes` `fp.widevine` | 屏幕/CPU/RAM/SOC/ABI/locale/时区/内核/Widevine L 级 → 喂服务端一致性 | JAVA/HARDWARE |
| **基站/WiFi 采集**（新） | `fp.cell_info` `fp.wifi_bssid` | 群控聚类输入；需 `ACCESS_FINE_LOCATION`，未授予则上报不可用、不加分 | JAVA |
| **环境完整性**（新） | `env.developer_options` `env.accessibility` `env.adb_wifi` | 无需特殊权限的环境信号（多为低风险，供服务端关联） | JAVA |
| **生态软件一致性**（新·原 D 节排除项） | `ecosystem.brand_mismatch` `ecosystem.no_gms` `ecosystem.inventory` | 声称品牌却缺该品牌特征系统包 / 无 GMS = 模拟器或伪造机型；另采集白名单生态清单喂服务端。**仅计分、无阻断点** | JAVA |
| **文件创建时间异常**（新·原 D 节排除项） | `filetime.install_before_build` `filetime.future_file` `filetime.crtime` ⚠️`filetime.uniform_install`(待验证) | 安装早于系统编译时间(真机不可能) / 文件时间在未来(时钟篡改) / crtime 经 native statx 采集；雷同性见下方待验证说明。**仅计分、无阻断点** | JAVA/NATIVE |
| 硬件背书 | `attest.key.*` | Key Attestation 本地解析 verifiedBoot/安全级别；Play Integrity 采集 | HARDWARE |
| **Play Integrity 错误码**（新） | `attest.play_integrity.env` | 令牌请求失败的 `IntegrityErrorCode` 无需解码即暴露 GMS/Play 环境：无 GMS/Play、无法绑定服务、`APP_UID_MISMATCH` 等。瞬时/网络/配置错误一律忽略。**仅计分、无阻断点** | JAVA |
| **GMS 签名采集**（新） | `ecosystem.inventory`(`vending_sig`/`gms_sig`) | 采集 `com.android.vending`/`gms` 签名 SHA-256，交服务端比对 Google 官方证书识别 microG/假 GMS（客户端不硬编证书常量、不本地裁决） | JAVA |

> 阻断点（命中即 100% 不可信）见 `ARCHITECTURE.md §13`，本轮新增信号中**无新增阻断点**——它们多为评分/采集类，刻意不做硬阻断以控误报。

> ⚠️ **`filetime.uniform_install` 前提待真机验证（勿轻信）**
> 该信号假设：「真机系统应用的 `firstInstallTime` 是**散开**的，只有模拟器/克隆/批量装机镜像才会让 ≥5 个包挤在**同一秒**」。
> **此前提尚未在真机上证实。** Android 的 `firstInstallTime` 存于 `/data/system/packages.xml`（`it`/`ut` 属性），预装系统应用很可能在**首次开机扫描**时被统一打上接近/相同的时间戳——若如此，**真机也会雷同**，本信号即为误报源。
> 我们一度用 redroid 容器的 `dumpsys package`（系统包时间戳确实雷同）来「印证」，但 **redroid 本身是非真机，用它推断真机属循环论证，不作数。**
> 处置：暂保留（MEDIUM×0.5、非阻断点、最坏轻微计分），**待用一台或多台正常使用过的真机采 `firstInstallTime` 分布后再决定保留 / 收紧阈值 / 删除**。在此之前不要把它当作可靠依据。

---

> **本轮新增端侧检查**：`emulator.qemu_prop`(原生·**新阻断点**) · `emulator.gpu_swiftshader`(GPU 软件渲染) · `emulator.missing_features` · `root.dangerous_props`(ro.secure/debuggable·原生) · `root.mounts`(magisk/KSU 挂载) · `tamper.signature_spoof`(签名交叉校验·防伪造) · `network.user_ca`(用户 CA/中间人) · `storage.scope`+`vspace.sandbox`(文件夹范围 + 沙盒标记)

## B. 🟦 阶段二·服务端（数据规模 / 关联 / 验签）

| 推演中的点 | 为什么必须放服务端 |
|---|---|
| **设备池一致性 / 群体基线(rarity)** | 需海量真机画像库算"这套属性是否罕见/自洽"；客户端无全网视角 |
| **设备图谱 / 团伙识别(GNN)** | 跨账号关系；资金链路、猫池号段、收券黄牛号最终在图上收敛 |
| **velocity / 同时段关联 / 超距同步** | 跨请求聚合；"低频慢速分布式"只在聚合端可见，单机看就是正常用户 |
| **TLS/JA3 · TCP/IP 栈指纹 vs 自报机型冲突** | 服务端才看得到连接的 TTL/Window/JA3；"设备与网络协议栈冲突"是关键特征 |
| **住宅代理 / IP 画像** | 服务端 IP 情报库 |
| **Play Integrity 解码 · Key Attestation 链验签** | 必须服务端用 Google API 解码、验链到硬件根 CA、查吊销；客户端只采集（已采） |
| **行为生物特征 / clickstream / LSTM·Transformer** | 序列建模在服务端；客户端可采 touch 但判定与 GAN 对抗在云 |
| **数据投毒 / 对抗样本鲁棒性** | 属模型训练与运营（决策边界监控、特征稳定性） |
| **动态挑战（无感验证/人脸/短信）** | 业务编排与风险分联动 |
| **多业务线联动风控** | 后端跨业务数据打通 |
| **肉鸡/挟持真账号** | 真机真指纹真网络，端侧几乎无解；只能靠行为基线+图谱（服务端） |
| **动态授信 / 考核期**（薅羊毛转化） | 跨时间窗的设备指纹稳定性观察，属服务端画像 |

---

## C. ⚠️ 客户端受限 / 不可靠（标注原因）

| 点 | 限制与处理 |
|---|---|
| **内核级 / syscall hook 检测** | 用户态探测对**内核 hook**返回"一切正常"。我们的 `hook.inline_hook` 只覆盖**用户态 libc**。基于 syscall 耗时的 timing-attack 噪声大、不稳定 → **暂不做**，留作研究项 |
| **"内核是否自己编译"** | 厂商 ROM(华为/小米/OPPO…)全是定制编译 → 误杀极高。**已改为**查 KernelSU/APatch 特征(`root.kernelsu`) |
| **弱网做风险加分** | 真用户(地铁/电梯)也弱网，黑产光纤+代理反而更稳 → **不作为风险**。网络属性只采集供服务端比对(协议栈冲突) |
| **TEE 伪装 / Key Attestation 本地解析** | 本地只能读证书里的值；真伪需服务端**验链到 Google 硬件根 CA**(阶段二)。本地解析结论标注"强但非权威" |
| **自动化 / 无障碍注入点击** | 需宿主在 View 层把 `MotionEvent` 交给 SDK 校验 `getToolType()`/`FLAG_WINDOW_IS_OBSCURED`。预留信号 `env.automation_input`，但**默认未接入** → 需宿主集成 |
| **悬浮窗覆盖(其它 App 的 SystemAlertWindow)** | 无法直接枚举他人窗口；只能靠被遮挡触摸标志(同上，需宿主接入) |
| **Play Integrity 本地判定模拟器** | 令牌（含 `MEETS_VIRTUAL_INTEGRITY` 等**判定结论**）加密，必须服务端解码 → 客户端只采集(`attest.play_integrity`)。**但请求失败的错误码可本地用**（见 A 节 `attest.play_integrity.env`），暴露 GMS/Play 环境真伪 |

---

## D. ⛔ 用户明令排除

| 点 | 状态 | 备注 |
|---|---|---|
| ~~**读取厂商生态软件做"型号↔系统应用一致性"**~~ | ✅ **已重新启用**（见 A 节 `ecosystem.*`） | 攻击者升级手段后按需求开启。**改用精选 `<queries>` 白名单**逐包 `getPackageInfo`（厂商特征包 + GMS），**不申请 `QUERY_ALL_PACKAGES`** → 规避了当初排除的审核风险。仅计分、非阻断点 |
| ~~**文件创建时间做内部指纹 / 时间差冲突**~~ | ✅ **已重新启用**（见 A 节 `filetime.*`） | crtime 经 native `statx(STATX_BTIME)` 采集（Java 拿不到 birth time）；安装早于系统编译、系统包装机时间雷同等异常计分。**仅计分、非阻断点**，靠 conf<1 + 24h SLACK 控制误报（定制 ROM / 无谷歌真机 / 时钟漂移） |

---

## E. 📋 Play Integrity 现状与优化空间（**仅状态记录，非实现计划/待办承诺**）

> 本节只**如实记录**当前 Play Integrity 走到哪一步、哪些能优化，**不构成要去实现的计划**。
> 是否动手、何时动手另行决策。

### 当前进度（把 PI 看成一条流水线）

| 步骤 | 状态 | 说明 |
|---|---|---|
| 1. 采集令牌 | ✅ | 用 **Classic** API（`IntegrityTokenRequest`），且**仅在配置了 `cloudProjectNumber` 时**才执行 |
| 2. 失败错误码本地计分 | ✅ | `attest.play_integrity.env`（无需解码即暴露 GMS/Play 环境；瞬时/网络/配置错误忽略） |
| 3. nonce 服务端下发、单次、绑定本次动作 | ❌ | 现状 nonce = **本地** `SecureRandom` challenge，未与服务端绑定 → 防重放/MITM 实际为空 |
| 4. 服务端解码令牌、读判定 | ❌ | `deviceIntegrity`(含 `MEETS_VIRTUAL_INTEGRITY`=模拟器) / `appIntegrity` / `accountDetails` 全靠这步 |
| 5. 按判定裁决（虚拟设备阻断点 `attest.play_integrity.virtual`） | ❌ | 已定义信号，属阶段二服务端，未建 |

> **结论：现停在「采集 + 本地看错误码」。令牌已收上来但未解码——其核心价值（判定结论）尚未兑现。**

### 可优化点（记录，未承诺实现）

**端侧：**
- **nonce 改为服务端下发**（即步骤 3）：本地生成的 nonce 防不住重放，截获的合法令牌可重复使用。这是让 PI 从「摆设」变「有用」的安全前提。
- **Classic vs Standard 取舍**：库（`integrity-1.4.0`）两套都在（`StandardIntegrityManager`/`StandardIntegrityTokenProvider` 等）。Standard 有预热、延迟低、适合高频；Classic（现状）每次全程往返、限流更紧，但每次新鲜、配服务端 nonce 防重放更强。**偶发风控场景倾向保留 Classic**，是否换取决于调用频率——真权衡，非「Standard 必然更好」。
- **gating 细化**：现在 `cloudProjectNumber==null` 直接跳过整段，连错误码环境信号也拿不到；可区分「未配置」与「环境报错」。
- **`appAccessRiskVerdict`**（PI 较新字段）可查屏幕共享/无障碍滥用等，正好补「自动化/无障碍注入」盲区——但**必须服务端解码**才能读。

**服务端（真正瓶颈，未建）：**
- 解密令牌 → 读判定、验 nonce/时间戳/包名/项目号 → 驱动 `attest.play_integrity.virtual` 阻断点。**步骤 4–5 才是 PI 的全部价值所在；端侧再优化也解锁不了它。**

### 已知验证缺口
- `attest.play_integrity.env` **未在设备现场触发过**（sample 未配 `cloudProjectNumber`，整段被跳过）——目前仅**编译 + 单测**覆盖。
- 全程仅在 redroid 容器验证，未在真机 / 真 GMS 环境验证。

---

## 一句话总结

> 端侧把"假设备/脚本/低端模拟器/已知 root-hook"尽量实锤掉，并采集**宽而可信**的属性；  
> 真正对付"改机+真机肉鸡+拟人行为+养号团伙"的，是**阶段二服务端的一致性校验 + 设备图谱 + velocity + 硬件背书验签**。两层缺一不可。
