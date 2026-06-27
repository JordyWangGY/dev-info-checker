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

    // —— Root ——
    const val ROOT_SU_BINARY = "root.su_binary"
    const val ROOT_MAGISK = "root.magisk"
    const val ROOT_TEST_KEYS = "root.test_keys"
    const val ROOT_RW_SYSTEM = "root.rw_system"
    const val ROOT_DANGEROUS_PROPS = "root.dangerous_props"
    const val ROOT_PACKAGES = "root.packages"

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

    // —— Tamper ——
    const val TAMPER_SIGNATURE = "tamper.signature"
    const val TAMPER_INSTALLER = "tamper.installer"
    const val TAMPER_SO_INTEGRITY = "tamper.so_integrity"

    // —— Network ——
    const val NETWORK_VPN = "network.vpn"
    const val NETWORK_PROXY = "network.proxy"

    // —— Fingerprint ——
    const val FP_STABLE_ID = "fp.stable_id"
    const val FP_INCONSISTENCY = "fp.inconsistency"

    // —— Attest（阶段一采集 / 本地解析，阶段二服务端验签）——
    const val ATTEST_KEY_CHAIN = "attest.key.cert_chain"
    const val ATTEST_PLAY_INTEGRITY = "attest.play_integrity.token"
    const val ATTEST_KEY_VERIFIED_BOOT_FAIL = "attest.key.verified_boot_fail"
    const val ATTEST_KEY_NOT_HARDWARE = "attest.key.not_hardware"
    const val ATTEST_PLAY_VIRTUAL = "attest.play_integrity.virtual"

    // —— Runtime（框架自身）——
    const val DETECTOR_ERROR = "runtime.detector_error"
    const val NATIVE_UNAVAILABLE = "runtime.native_unavailable"
}
