package com.devcheck.protocol

/**
 * 信号 ID 目录（单一事实源，客户端与服务端共用）。
 * 命名规范：`<category>.<check>`，全小写下划线。
 */
object Signals {
    // —— Emulator ——
    const val EMULATOR_BUILD_PROPS = "emulator.build_props"
    const val EMULATOR_FILES = "emulator.qemu_files"
    const val EMULATOR_QEMU_PIPE = "emulator.qemu_pipe"
    const val EMULATOR_GPU = "emulator.gpu_swiftshader"
    const val EMULATOR_NO_SENSORS = "emulator.no_sensors"
    const val EMULATOR_CPU_ARCH = "emulator.cpu_x86_on_arm"
    const val EMULATOR_SENSOR_STATIC = "emulator.sensor_static" // 传感器零方差/恒定值=伪造
    const val EMULATOR_QEMU_PROP = "emulator.qemu_prop"         // ro.kernel.qemu=1 (原生读)
    const val EMULATOR_MISSING_FEATURES = "emulator.missing_features" // 缺触屏/电话/相机/蓝牙
    // —— Cloud phone / 容器化(共享内核) 检测（ARM-on-ARM，经典 x86/QEMU/clocksource 检测失效）——
    const val CLOUD_KERNEL = "emulator.cloud_kernel"         // /proc/version 宿主 Linux 内核串(Ubuntu/gcc/-generic)
    const val CLOUD_DISK = "emulator.cloud_disk"             // /proc/partitions virtio vda/sr0, 无 mmcblk/UFS
    const val CLOUD_PCI = "emulator.cloud_pci"               // /sys/bus/pci/devices 非空(手机无 PCI 总线)
    const val CLOUD_INPUT = "emulator.cloud_input"           // /proc/bus/input/devices QEMU/Virtual 输入
    const val CLOUD_CGROUP = "emulator.cloud_cgroup"         // /proc/self/cgroup systemd/docker/lxc 容器痕迹
    const val CLOUD_NET = "emulator.cloud_net"               // /sys/class/net 只有 eth0、无 wlan0/rmnet
    const val CLOUD_NO_BATTERY = "emulator.cloud_no_battery" // /sys/class/power_supply 无 battery(HAL 假造)
    const val CLOUD_SOUNDCARD = "emulator.cloud_soundcard"   // /proc/asound/cards HDA Intel/QEMU 虚拟声卡
    const val CLOUD_INFO = "emulator.cloud_info"             // 采集: 内核/磁盘/网卡/PCI/SoC/热区/调频(喂服务端)

    // —— SELinux / 安全上下文（容器/云机最早露馅的一层；真机锁定态恒 enforcing）——
    const val EMULATOR_SELINUX_PERMISSIVE = "emulator.selinux_permissive" // 非 enforcing(permissive/disabled)
    const val EMULATOR_SELINUX_CONTEXT = "emulator.selinux_context"       // 自身域非规范 untrusted_app/缺 MLS 类别
    const val EMULATOR_SELINUX_FS = "emulator.selinux_fs"                 // selinuxfs 缺失(真机必有)
    const val EMULATOR_SELINUX_INFO = "emulator.selinux_info"             // 采集: enforce/context/mode (喂服务端一致性)

    // —— Root ——
    const val ROOT_SU_BINARY = "root.su_binary"
    const val ROOT_MAGISK = "root.magisk"
    const val ROOT_TEST_KEYS = "root.test_keys"
    const val ROOT_RW_SYSTEM = "root.rw_system"
    const val ROOT_DANGEROUS_PROPS = "root.dangerous_props"
    const val ROOT_PACKAGES = "root.packages"
    const val ROOT_KERNELSU = "root.kernelsu" // KernelSU / APatch 等内核级提权
    const val ROOT_MOUNTS = "root.mounts"     // magisk/KSU/APatch 挂载痕迹

    // —— Hook ——
    const val HOOK_XPOSED = "hook.xposed"
    const val HOOK_FRIDA_MAPS = "hook.frida.maps"
    const val HOOK_FRIDA_PORT = "hook.frida.port"
    const val HOOK_FRIDA_THREADS = "hook.frida.threads"
    const val HOOK_INLINE = "hook.inline_hook"
    const val HOOK_SUBSTRATE = "hook.substrate"

    // —— Debug ——
    const val DEBUG_DEBUGGER = "debug.debugger"
    const val DEBUG_TRACERPID = "debug.tracerpid"
    const val DEBUG_ADB = "debug.adb_enabled"
    const val DEBUG_DEBUGGABLE = "debug.debuggable_flag"

    // —— VirtualSpace ——
    const val VSPACE_DATA_PATH = "vspace.data_path"
    const val VSPACE_FOREIGN_APK = "vspace.maps_foreign_apk"
    const val VSPACE_CLASSLOADER = "vspace.classloader"   // 沙盒框架类加载器/路径特征
    const val VSPACE_PROCESS_NAME = "vspace.process_name" // 进程名 base != 包名
    const val VSPACE_SANDBOX = "vspace.sandbox"           // app 自有目录被沙盒重定向(特别标记)
    const val VSPACE_FOREIGN_DIR = "vspace.foreign_dir"   // 可列出他人 data 目录(非隔离环境)

    // —— Tamper ——
    const val TAMPER_SIGNATURE = "tamper.signature"
    const val TAMPER_SIG_SPOOF = "tamper.signature_spoof" // PM 签名 vs APK 文件签名 不一致
    const val TAMPER_INSTALLER = "tamper.installer"
    const val TAMPER_SO_INTEGRITY = "tamper.so_integrity"

    // —— Network ——
    const val NETWORK_VPN = "network.vpn"
    const val NETWORK_PROXY = "network.proxy"
    const val NETWORK_USER_CA = "network.user_ca" // 用户/MDM 安装的 CA(中间人抓包)

    // —— Fingerprint（采集为主，自洽/一致性判定在服务端）——
    const val FP_STABLE_ID = "fp.stable_id"
    const val FP_INCONSISTENCY = "fp.inconsistency"
    const val FP_ATTRIBUTES = "fp.attributes"   // 全面属性集（屏幕/CPU/RAM/SOC/ABI/locale/时区/内核…）
    const val FP_WIDEVINE = "fp.widevine"       // Widevine DRM 安全级别 L1/L3
    const val FP_WIFI = "fp.wifi_bssid"         // 连接 WiFi BSSID（需定位权限）
    const val FP_CELL = "fp.cell_info"          // 基站信息（需定位权限）
    const val STORAGE_SCOPE = "storage.scope"   // app 可达文件夹范围(自有目录+系统/共享目录)

    // —— Ecosystem（系统生态软件一致性：声称机型 ↔ 厂商系统应用）——
    const val ECOSYSTEM_BRAND_MISMATCH = "ecosystem.brand_mismatch" // 声称品牌却无该品牌任一特征系统包
    const val ECOSYSTEM_NO_GMS = "ecosystem.no_gms"                 // GMS 基线全缺（弱信号，无谷歌真机合法存在）
    const val ECOSYSTEM_INVENTORY = "ecosystem.inventory"          // 白名单生态包命中清单（采集，喂服务端）

    // —— FileTime（文件创建时间 / 时间戳异常：时钟篡改 / 克隆镜像）——
    const val FILETIME_INSTALL_BEFORE_BUILD = "filetime.install_before_build" // App 安装早于系统编译时间(真机不可能)
    const val FILETIME_UNIFORM_INSTALL = "filetime.uniform_install"           // 多系统包安装时间精确雷同=批量装机镜像
    const val FILETIME_FUTURE_FILE = "filetime.future_file"                   // 关键文件时间在未来=时钟篡改
    const val FILETIME_CRTIME = "filetime.crtime"                             // 真实创建时间(statx btime, 采集)

    // —— Environment（运行环境完整性）——
    const val ENV_DEVELOPER_OPTIONS = "env.developer_options"
    const val ENV_ACCESSIBILITY = "env.accessibility"
    const val ENV_ADB_WIFI = "env.adb_wifi"
    const val ENV_MOCK_LOCATION = "env.mock_location"
    const val ENV_AUTOMATION_INPUT = "env.automation_input" // 自动化/无障碍注入点击（需宿主接入）

    // —— Attest（阶段一采集 / 本地解析，阶段二服务端验签）——
    const val ATTEST_KEY_CHAIN = "attest.key.cert_chain"
    const val ATTEST_PLAY_INTEGRITY = "attest.play_integrity.token"
    const val ATTEST_KEY_VERIFIED_BOOT_FAIL = "attest.key.verified_boot_fail"
    const val ATTEST_KEY_NOT_HARDWARE = "attest.key.not_hardware"
    const val ATTEST_PLAY_VIRTUAL = "attest.play_integrity.virtual"
    const val ATTEST_PLAY_ENV = "attest.play_integrity.env" // 令牌请求失败的错误码暴露 GMS/Play 环境(本地, 仅计分)

    // —— Runtime（框架自身）——
    const val DETECTOR_ERROR = "runtime.detector_error"
    const val NATIVE_UNAVAILABLE = "runtime.native_unavailable"
}
