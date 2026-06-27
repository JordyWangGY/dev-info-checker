package com.devcheck.protocol

/**
 * 客户端检测点目录：枚举所有「实际执行」的检测项（即使本次未命中也能展示）。
 * UI 的「检测点」页据此显示 通过 / 已采集 / 命中 三态。
 * 纯服务端项（如 Play Integrity 模拟器判定）与规划项不在此列。
 */
object Catalog {

    data class Point(val id: String, val category: Category, val desc: String)

    val ALL: List<Point> = listOf(
        // Emulator
        Point(Signals.EMULATOR_BUILD_PROPS, Category.EMULATOR, "Build 指纹 / 机型黑名单"),
        Point(Signals.EMULATOR_FILES, Category.EMULATOR, "QEMU / Genymotion 文件"),
        Point(Signals.EMULATOR_QEMU_PIPE, Category.EMULATOR, "QEMU 管道设备 (原生)"),
        Point(Signals.EMULATOR_CPU_ARCH, Category.EMULATOR, "x86 ABI"),
        Point(Signals.EMULATOR_NO_SENSORS, Category.EMULATOR, "缺失关键传感器"),
        Point(Signals.EMULATOR_SENSOR_STATIC, Category.EMULATOR, "传感器静态 / 零方差"),
        Point(Signals.EMULATOR_QEMU_PROP, Category.EMULATOR, "ro.kernel.qemu 属性 (原生)"),
        Point(Signals.EMULATOR_GPU, Category.EMULATOR, "GPU 软件渲染 (SwiftShader 等)"),
        Point(Signals.EMULATOR_MISSING_FEATURES, Category.EMULATOR, "关键系统特性缺失"),
        // Root
        Point(Signals.ROOT_SU_BINARY, Category.ROOT, "su 二进制"),
        Point(Signals.ROOT_MAGISK, Category.ROOT, "Magisk 痕迹"),
        Point(Signals.ROOT_KERNELSU, Category.ROOT, "KernelSU / APatch"),
        Point(Signals.ROOT_TEST_KEYS, Category.ROOT, "test-keys 签名"),
        Point(Signals.ROOT_PACKAGES, Category.ROOT, "Root 管理器应用"),
        Point(Signals.ROOT_RW_SYSTEM, Category.ROOT, "system 分区可写"),
        Point(Signals.ROOT_DANGEROUS_PROPS, Category.ROOT, "危险系统属性 (ro.secure/debuggable)"),
        Point(Signals.ROOT_MOUNTS, Category.ROOT, "magisk/KSU 挂载痕迹"),
        // Hook
        Point(Signals.HOOK_FRIDA_MAPS, Category.HOOK, "Frida 内存映射"),
        Point(Signals.HOOK_FRIDA_PORT, Category.HOOK, "Frida 默认端口"),
        Point(Signals.HOOK_FRIDA_THREADS, Category.HOOK, "Frida 线程名"),
        Point(Signals.HOOK_XPOSED, Category.HOOK, "Xposed / LSPosed"),
        Point(Signals.HOOK_SUBSTRATE, Category.HOOK, "Substrate"),
        Point(Signals.HOOK_INLINE, Category.HOOK, "inline hook 跳板 (原生)"),
        // Debug
        Point(Signals.DEBUG_DEBUGGER, Category.DEBUG, "调试器连接"),
        Point(Signals.DEBUG_TRACERPID, Category.DEBUG, "ptrace 跟踪 (TracerPid)"),
        Point(Signals.DEBUG_ADB, Category.DEBUG, "ADB 开启"),
        Point(Signals.DEBUG_DEBUGGABLE, Category.DEBUG, "debuggable 标志"),
        // VirtualSpace
        Point(Signals.VSPACE_DATA_PATH, Category.VSPACE, "data/files 路径异常"),
        Point(Signals.VSPACE_PROCESS_NAME, Category.VSPACE, "进程名 ≠ 包名"),
        Point(Signals.VSPACE_CLASSLOADER, Category.VSPACE, "沙盒类加载器 / 路径"),
        Point(Signals.VSPACE_FOREIGN_APK, Category.VSPACE, "映射他包 apk"),
        Point(Signals.VSPACE_SANDBOX, Category.VSPACE, "app 目录被沙盒重定向"),
        Point(Signals.VSPACE_FOREIGN_DIR, Category.VSPACE, "可列出他人 data 目录"),
        // Tamper
        Point(Signals.TAMPER_SIGNATURE, Category.TAMPER, "签名校验"),
        Point(Signals.TAMPER_SIG_SPOOF, Category.TAMPER, "签名交叉校验 (防伪造)"),
        Point(Signals.TAMPER_INSTALLER, Category.TAMPER, "安装来源"),
        Point(Signals.TAMPER_SO_INTEGRITY, Category.TAMPER, ".so 自校验 (原生)"),
        // Network
        Point(Signals.NETWORK_VPN, Category.NETWORK, "VPN"),
        Point(Signals.NETWORK_PROXY, Category.NETWORK, "系统代理"),
        Point(Signals.NETWORK_USER_CA, Category.NETWORK, "用户安装 CA (中间人)"),
        // Fingerprint（采集）
        Point(Signals.FP_ATTRIBUTES, Category.FINGERPRINT, "全面属性采集"),
        Point(Signals.FP_WIDEVINE, Category.FINGERPRINT, "Widevine 安全级别"),
        Point(Signals.FP_WIFI, Category.FINGERPRINT, "WiFi BSSID (需定位权限)"),
        Point(Signals.FP_CELL, Category.FINGERPRINT, "基站信息 (需定位权限)"),
        Point(Signals.STORAGE_SCOPE, Category.FINGERPRINT, "可达文件夹范围扫描"),
        // Environment
        Point(Signals.ENV_DEVELOPER_OPTIONS, Category.ENVIRONMENT, "开发者选项"),
        Point(Signals.ENV_ACCESSIBILITY, Category.ENVIRONMENT, "无障碍服务"),
        Point(Signals.ENV_ADB_WIFI, Category.ENVIRONMENT, "无线调试"),
        // Attest（采集 / 本地解析）
        Point(Signals.ATTEST_KEY_CHAIN, Category.ATTEST, "Key Attestation 证书链"),
        Point(Signals.ATTEST_KEY_VERIFIED_BOOT_FAIL, Category.ATTEST, "verified boot 状态"),
        Point(Signals.ATTEST_KEY_NOT_HARDWARE, Category.ATTEST, "TEE / 硬件安全级别"),
        Point(Signals.ATTEST_PLAY_INTEGRITY, Category.ATTEST, "Play Integrity 令牌"),
    )
}
