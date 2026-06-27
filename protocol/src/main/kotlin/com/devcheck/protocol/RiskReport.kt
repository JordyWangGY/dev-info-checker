package com.devcheck.protocol

import kotlinx.serialization.Serializable

/**
 * 一次检测的完整结果。阶段一由客户端 LocalRiskScorer 生成（本地分）；
 * 阶段二的权威分与 [decisionJwt] 由服务端回填。
 */
@Serializable
data class RiskReport(
    val verdict: Verdict,
    val score: Int,                                   // 0..100，0=干净
    val signals: List<Signal>,
    val categoryScores: Map<Category, Int> = emptyMap(),
    val elapsedMs: Long = 0,
    val nativeAvailable: Boolean = false,
    /** 命中的阻断点（100% 不可信的决定性证据）；非空即 verdict=COMPROMISED。 */
    val blockingSignals: List<Signal> = emptyList(),
    val schemaVersion: Int = 1,
    /** 阶段二：服务端签名的权威裁决令牌，透传给业务后端校验。 */
    val decisionJwt: String? = null,
) {
    val isTrusted: Boolean get() = verdict == Verdict.GENUINE
}
