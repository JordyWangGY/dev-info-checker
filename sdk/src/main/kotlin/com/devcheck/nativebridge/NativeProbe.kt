package com.devcheck.nativebridge

/**
 * JNI 桥。阶段一 1.2 会补齐 C++ 实现（libdevcheck.so）：直接 syscall 读 /proc、
 * 反 ptrace、inline-hook 检测、.so 自校验等，绕过 libc / Java 层 hook。
 *
 * 设计要点：**优雅降级**。当 .so 缺失（未装 NDK / 未编译）时 [isAvailable]=false，
 * 所有方法返回空/默认值，由上层产出 `runtime.native_unavailable` 信号，
 * 而非崩溃或误判为「通过」。
 */
object NativeProbe {

    @Volatile
    var isAvailable: Boolean = false
        private set

    init {
        isAvailable = try {
            System.loadLibrary("devcheck")
            true
        } catch (t: Throwable) {
            false
        }
    }

    /** /proc/self/status 的 TracerPid；返回 -1 表示原生不可用（上层走 Java 兜底）。 */
    fun tracerPid(): Int = if (isAvailable) nativeTracerPid() else -1

    /** 扫描 /proc/self/maps 命中的可疑库（frida / gum / lspd / substrate / magisk ...）。 */
    fun suspiciousMaps(): Array<String> = if (isAvailable) nativeSuspiciousMaps() else emptyArray()

    /** 用 syscall faccessat 直接探测路径是否存在（绕过 libc hook）。 */
    fun pathExists(path: String): Boolean = if (isAvailable) nativePathExists(path) else false

    /** 关键 libc 函数序言被改写为 hook 跳板（inline hook）的函数名列表。 */
    fun inlineHookedFns(): Array<String> = if (isAvailable) nativeInlineHooked() else emptyArray()

    /** 本 SDK 原生库代码段是否「可写且可执行」（正常应 r-x；可写=被打补丁前置条件）。 */
    fun codeWritable(): Boolean = if (isAvailable) nativeCodeWritable() else false

    private external fun nativeTracerPid(): Int
    private external fun nativeSuspiciousMaps(): Array<String>
    private external fun nativePathExists(path: String): Boolean
    private external fun nativeInlineHooked(): Array<String>
    private external fun nativeCodeWritable(): Boolean
}
