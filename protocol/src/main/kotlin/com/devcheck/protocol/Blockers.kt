package com.devcheck.protocol

/**
 * 阻断点（Blocker）名录 —— **命中任一即判定环境 100% 不可信，强制 [Verdict.COMPROMISED]**。
 *
 * 入选标准（缺一不可）：
 *  1. **dispositive（决定性）**：在合法、未被篡改的真机上其误报率≈0；
 *  2. **来源可信**：证据由 NATIVE（直接 syscall，绕过 libc/Java hook）或 HARDWARE（硬件背书）产出。
 *     —— 纯 Java 来源的「同名」信号只计入评分、**不**触发阻断，因为 Java 层可被 hook 伪造，
 *        不足以支撑「100%」结论（参见 [Scoring.isBlocker]）。
 *
 * 逐项列出（reason 解释「为何是 100%」，trust 为可信来源，phase 为生效阶段）：
 */
object Blockers {

    enum class Trust { NATIVE, HARDWARE }

    data class Blocker(
        val id: String,
        val reason: String,
        val trust: Trust,
        val phase: String,
    )

    val ALL: List<Blocker> = listOf(
        // —— 运行时注入（原生确认）——
        Blocker(
            Signals.HOOK_FRIDA_MAPS,
            "本进程地址空间内映射了 frida-agent / gum（原生 syscall 读 /proc/self/maps 确认）；合法 App 进程绝不会加载它",
            Trust.NATIVE, "1.2",
        ),
        Blocker(
            Signals.HOOK_INLINE,
            "关键 libc / JNI 函数序言被改写为跳板指令（inline hook）；运行时已被注入篡改",
            Trust.NATIVE, "1.4 ✅",
        ),
        Blocker(
            Signals.DEBUG_TRACERPID,
            "原生确认 TracerPid≠0：有调试器 / Frida 通过 ptrace attach 到本进程",
            Trust.NATIVE, "1.2",
        ),
        // —— 模拟器（原生确认）——
        Blocker(
            Signals.EMULATOR_QEMU_PIPE,
            "存在 QEMU 管道设备 /dev/qemu_pipe、/dev/socket/qemud（原生 syscall faccessat 确认）；仅模拟器具备",
            Trust.NATIVE, "1.2",
        ),
        Blocker(
            Signals.EMULATOR_QEMU_PROP,
            "系统属性 ro.kernel.qemu=1（原生 __system_property_get 读取）；QEMU 模拟器实锤",
            Trust.NATIVE, "1.x ✅",
        ),
        // —— 二进制完整性（原生自校验）——
        Blocker(
            Signals.TAMPER_SO_INTEGRITY,
            "SDK 原生库 .so 代码段被改写（可写可执行映射 / 序言被打补丁）；二进制完整性破坏",
            Trust.NATIVE, "1.4 ✅",
        ),
        // —— 硬件背书（最强，攻击者无法在普通设备伪造）——
        Blocker(
            Signals.ATTEST_KEY_VERIFIED_BOOT_FAIL,
            "硬件 Key Attestation：verifiedBootState ≠ GREEN（引导链未验证 / 解锁 / 自编系统）",
            Trust.HARDWARE, "1.3 ✅本地解析 · 2.0 服务端验签",
        ),
        Blocker(
            Signals.ATTEST_KEY_NOT_HARDWARE,
            "Key Attestation 证书链无法回溯到 Google 硬件根 CA，或安全级别=SOFTWARE；无真实 TEE（模拟器 / 伪造）",
            Trust.HARDWARE, "1.3 ✅本地(securityLevel) · 2.0 链验签",
        ),
        Blocker(
            Signals.ATTEST_PLAY_VIRTUAL,
            "Play Integrity 返回 MEETS_VIRTUAL_INTEGRITY 或缺 MEETS_DEVICE_INTEGRITY；Google 判定为模拟器 / 非完整设备",
            Trust.HARDWARE, "2.0 服务端解码",
        ),
    )

    /** 阻断点信号 ID 集合（供 [Scoring.isBlocker] 快速判定）。 */
    val IDS: Set<String> = ALL.map { it.id }.toSet()

    fun of(id: String): Blocker? = ALL.firstOrNull { it.id == id }
}
