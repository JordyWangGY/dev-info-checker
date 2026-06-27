package com.devcheck.protocol

import kotlinx.serialization.Serializable

/**
 * 统一证据单元。每个 Detector 产出 0..N 条 Signal。
 *
 * @param id        全局稳定命名空间，见 [Signals]，例如 "root.su_binary"
 * @param category  所属类别
 * @param severity  严重度（→ 评分权重）
 * @param confidence 单条证据可信度 0f..1f（启发式信号通常 < 1）
 * @param source    证据来源（Java / Native / 硬件），越底层越难伪造
 * @param evidence  原始证据键值对，便于服务端复核与离线分析
 * @param blocking  是否为「阻断点」：命中即 100% 不可信，强制 COMPROMISED（见 [Blockers]）
 */
@Serializable
data class Signal(
    val id: String,
    val category: Category,
    val severity: Severity,
    val confidence: Float = 1f,
    val source: Source = Source.JAVA,
    val evidence: Map<String, String> = emptyMap(),
    /** 通常无需手动设置：可信来源(NATIVE/HARDWARE)的名录信号会被 [Scoring.isBlocker] 自动识别为阻断点。 */
    val blocking: Boolean = false,
)
