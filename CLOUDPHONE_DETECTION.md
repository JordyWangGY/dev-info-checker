# 云手机 / 容器化 Android 端侧检测点调研

> 目标：普通 App（**无 root**）能读哪些本地信号，判定当前是**云手机/容器/虚拟机**而非真机。
> 方法：① 在一台**真·云手机**上实测（设备自称 `Xiaomi 25019PNF3C / Android 15`，实为 redroid 类容器）；② deep-research 多源网络调研（102 agent / 263 次检索）。
> **诚实标注**：web 调研的「合成 + 部分对抗验证」步骤撞上了会话速率限制，故网络侧只有 5 条达到 3-0/2-0 核实，其余为**未完成验证的线索**（非「被驳倒」）。实测项标 ✓实测、网络核实标 ✓web、线索标 ⚠️待验。仅一台云机实测、无真机做误报基线——零误报靠逻辑推理 + 服务端复核。

## 核心认知（决定优先级）

- 云手机多是 **ARM-on-ARM 的共享内核容器**（redroid = Android 用户态跑在宿主 Linux 内核上，靠 binder/ashmem 模块，无 QEMU/无虚拟化扩展）。→ **经典 x86/QEMU/goldfish 检测、clocksource(kvm-clock) 全部失效**（本机 clocksource=`arch_sys_counter` 真 ARM 值）。
- 真正暴露它的是：**内核串、容器痕迹、真实硬件缺失、GPU 虚拟化**。
- **`ro.*` 属性可被云机覆盖**（web 线索）→ 属性类信号（含 `ro.hardware`）易被隐藏，**权重不宜高**；难伪造的是 `/proc`、`/sys`、`/dev`、内核串、GPU 渲染器。

## 检测点清单（按方向）

### A. 内核 / 容器痕迹（最硬，多为无 root 可读）
| 检测点 | 读什么 | 判据 | 无root | 误报 | 强度 | 来源 |
|---|---|---|---|---|---|---|
| 内核构建串 | `/proc/version`（native readText）；`os.version` | 含 `Ubuntu`/`gcc`/`-generic`/`buildd@` = 宿主 Linux 内核；真机是 clang 构建的 vendor 内核 | ✅ | 低 | **极强** | ✓实测 |
| systemd cgroup | `/proc/self/cgroup` | 出现 `name=systemd` / cgroup 路径异常(`/uid_0/pid_x`) = 容器；Android 用 init 无 systemd | ✅ | 低 | **强** | ✓实测 |
| `ro.hardware` | `ro.hardware`/`ro.boot.hardware` | ∈ 云机名单(`redroid`…) | ✅ | 低 | 强(但**易被覆盖**) | ✓实测 |
| 宿主内核模块 | `lsmod`/`/proc/modules` | `binder_linux`/`ashmem_linux`/`memfd` 非标准模块 | ❌需root | — | 中 | ✓web |

### B. 真实硬件缺失 / 虚拟外设（多为无 root 可读）
| 检测点 | 读什么 | 判据 | 无root | 误报 | 强度 | 来源 |
|---|---|---|---|---|---|---|
| 虚拟磁盘布局 | `/proc/partitions`、`/dev/block` | virtio `vda`、CD-ROM `sr0`、成片 `loopN`，**无 `mmcblk`/UFS(`sda`)** | ✅ | 低 | **强** | ✓实测 |
| 无存储序列号 | `/sys/block/mmcblk0/device/serial`\|`cid`、`/sys/devices/soc0/serial_number` | 缺失/空 = 无真实 eMMC/UFS/SoC | ✅(路径通常可读) | 中 | 中强 | ⚠️待验 |
| 虚拟输入设备 | `/proc/bus/input/devices` | `QEMU … USB Tablet/Mouse`、`Virtual Touchscreen`、`goldfish`，无真实触屏驱动(fts/goodix/synaptics) | ✅ | 低 | **强** | ✓实测 |
| 无热区 | `/sys/class/thermal/` | 空/无 `thermal_zoneN` | ✅ | 中 | 中 | ✓实测 |
| CPU 实现者↔机型 | `/proc/cpuinfo` `CPU implementer`/`part` | 与机型矛盾(本机 `0x61`=Apple 却称 Xiaomi)；缺 `Hardware:` 行 | ✅ | 中(需机型映射) | 中强 | ✓实测 |
| 无基带 | `gsm.version.baseband`、telephony | 空/无 modem | ✅ | 中(WiFi 平板合法) | 中 | ✓实测 |
| device-tree 缺 | `/proc/device-tree/compatible` | 不存在（真 ARM 设备有） | ⚠️读取权限不稳 | 中 | 中 | ✓实测 |

### C. GPU 虚拟化（web 核实的一整条线，无 root 可读）
| 检测点 | 读什么 | 判据 | 无root | 误报 | 强度 | 来源 |
|---|---|---|---|---|---|---|
| GL 渲染器串 | `glGetString(GL_RENDERER)` | `virgl (Mali-*)`、`llvmpipe (LLVM…)`、`zink … (Driver Unknown)`、`SwiftShader`/`ANGLE` = 虚拟/软件渲染；真机是 `Adreno`/`Mali` 原生串 | ✅ | 低 | **强** | ✓web + ✓实测(本机 SwiftShader/ANGLE) |
| Vulkan 设备名 | `VkPhysicalDeviceProperties.deviceName`/driver | `Virtio-GPU Venus`、`SwiftShader` | ✅ | 低 | 强 | ✓web |
| GPU 设备节点 | `/dev/dri` vs `/dev/mali`\|`kgsl` | 只有 `dri`(桌面 DRM)、无 `mali/kgsl`(真 ARM GPU 节点) | ✅ | 中 | 中 | ✓实测 |

> 注：`emulator.gpu_swiftshader`（软件渲染）我们**已实现**——本机正是被它也能抓到。GPU 线的**增量**是补 `virgl`/`Virtio-GPU Venus`/`zink`/`llvmpipe` 这些**虚拟化(非纯软件)**渲染器串。

### D. 群控 / 设备农场（主要服务端）
| 检测点 | 读什么 | 判据 | 无root | 强度 | 来源 |
|---|---|---|---|---|---|
| boot_id | `/proc/sys/kernel/random/boot_id` | 海量设备同一 boot_id / 采集供服务端聚类 | ✅(采集) | 服务端 | ⚠️待验 |
| 指纹一致性 | build fingerprint / ro.product.* | 同机型海量完全一致 = 农场 | 采集 | 服务端 | ✓实测(需规模) |

### E. 已验证「无效/不适用」（诚实记录，避免白做）
- **clocksource**（`/sys/.../current_clocksource`）：只对 **x86 KVM VM**(kvm-clock/tsc)有效；ARM 云机=`arch_sys_counter`(真 ARM 值)，**不暴露** —— 本机实测证实。
- `/proc/cmdline` 里的 `androidboot.redroid_*`：**shell 都 Permission denied**，App 更读不到 → 不可用（web 声称可读，实测否定）。
- 传感器数量/相机数：redroid 注入假传感器(本机 69 个)/假相机(1 个) → 数量不构成 tell。

### F. 补充检测点（第二轮实测，均无 root 可读）
| 检测点 | 读什么 | 判据 | 无root | 误报 | 强度 | 来源 |
|---|---|---|---|---|---|---|
| 网络接口异常 | `/sys/class/net`（列目录） | 只有 `eth0`+`lo`，**无 `wlan0`/`rmnet_data*`/`ccmni*`** = 数据中心网卡；真机有 WiFi/蜂窝接口 | ✅ | 低 | **强** | ✓实测 |
| sysfs 无电池 | `/sys/class/power_supply/`（列目录） | **空/无 `battery`**，但 framework `BatteryManager` 却报电量/温度 = HAL 假造电池（矛盾） | ✅ | 低 | **强** | ✓实测 |
| 无 SoC 节点 | `/sys/devices/soc0/`（`machine`/`soc_id`/`serial_number`） | 缺失 = 非真实高通 SoC（对声称高通机型） | ✅ | 中(仅高通) | 强 | ✓实测 |
| 无 CPU 调频 | `/sys/devices/system/cpu/cpu0/cpufreq/scaling_*` | 不存在 = 无真实 DVFS（宿主管频） | ✅ | 中 | 中强 | ✓实测 |
| 无序列号 | `ro.serialno`/`ro.boot.serialno`、`Build.getSerial()` | 空 | ✅ | 中(隐私设置) | 中 | ✓实测 |
| 构建主机串 | `ro.build.host`/`ro.build.user` | k8s 构建 pod 名(`pangu-build-…-s9vkd-rlxnj-p3rhm`)、`builder` 等 CI 特征 | ✅ | 中(可能撞真 OEM CI) | 中/采集 | ✓实测 |
| 内存/开机时间 | `/proc/meminfo` MemTotal、`/proc/uptime`、`/proc/stat` btime | 与机型标称 RAM 不符 / 供服务端聚类 | ✅(采集) | — | 服务端 | ✓实测 |
| 二进制翻译库 | `/proc/self/maps` | 含 `libhoudini`/`libndk_translation` = **x86 云机**跑 ARM 应用（本机为 ARM，未命中） | ✅ | 低 | 中(仅 x86 云机) | ✓web/实测(阴性) |

## 最值得优先加入 SDK 的 Top 候选（按性价比·难伪造·无root）
1. **内核构建串**（`/proc/version` 含 Ubuntu/gcc/-generic）——极强、难伪造、native 可读。
2. **虚拟磁盘布局**（`/proc/partitions`：vda/sr0/loop 泛滥、无 mmcblk/UFS）——强、难伪造。
3. **虚拟输入设备**（`/proc/bus/input/devices`：QEMU/Virtual，无真实触屏驱动）——强。
4. **systemd cgroup**（`/proc/self/cgroup` 含 systemd）——强。
5. **GPU 虚拟化渲染器串补全**（virgl/Venus/zink/llvmpipe；SwiftShader 已覆盖）——强，需宿主在 GL/Vulkan 上下文取串。
6. **网络接口异常**（`/sys/class/net` 只有 `eth0`、无 `wlan0`/`rmnet`）——强、难伪造、列目录即可。
7. **sysfs 无电池**（`/sys/class/power_supply` 空 vs framework 报电量）——强、难伪造。
8. **无 SoC 节点 / 无存储序列号**（`/sys/devices/soc0/`、`/sys/block/mmcblk0/device/serial` 缺失）——中强（⚠️先在真机验证路径可读性）。
9. 无 CPU 调频、CPU implementer↔机型矛盾、无热区、无基带、无序列号——中强，作补充计分。

> 与现有实现关系：GPU-SwiftShader、SELinux 上下文、传感器零方差、生态一致性、Key Attestation/Play Integrity 已覆盖；上面 1–4、6、7 均为**增量**。全部建议**仅计分**（ARM 云机上单条都可能被针对性伪造，靠多信号叠加 + 服务端一致性）。

## 待办（速率限制导致未竟）
- deep-research 的合成/验证未跑完（12:20 重置）；本文的 ⚠️待验 项需补一轮核实 + 真机验证路径可读性与误报。
- 真机基线：本调研只在**一台云机**实测，缺真机做零误报确认。
