package com.devcheck.protocol

import kotlinx.serialization.Serializable

/** 检测类别。每个 Detector 归属一个类别；评分时按类别封顶以防单类堆叠刷分。 */
@Serializable
enum class Category {
    EMULATOR,    // 模拟器
    ROOT,        // Root / 提权
    HOOK,        // Xposed / Frida / Substrate 等运行时注入
    DEBUG,       // 调试器 / ptrace / ADB
    VSPACE,      // 多开 / 虚拟空间
    TAMPER,      // 重打包 / 签名篡改 / 完整性
    NETWORK,     // VPN / 代理
    FINGERPRINT, // 设备指纹与自洽性
    ATTEST,      // 硬件背书（Play Integrity / Key Attestation）
    RUNTIME,     // 检测框架自身的运行时状态（如 native 不可用、detector 异常）
}

/** 单条信号的严重度，决定评分权重。 */
@Serializable
enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

/** 信号来源，越靠近硬件越可信。 */
@Serializable
enum class Source { JAVA, NATIVE, HARDWARE }

/** 最终裁决等级。 */
@Serializable
enum class Verdict {
    GENUINE,      // 可信
    LOW_RISK,     // 轻度可疑
    SUSPICIOUS,   // 可疑，建议加验证
    HIGH_RISK,    // 高危
    COMPROMISED,  // 环境不可信
    UNKNOWN,      // 未能评估（离线 / 超时 / 未初始化）
}
