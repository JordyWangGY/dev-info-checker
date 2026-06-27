package com.devcheck.core

import com.devcheck.protocol.RiskReport
import com.devcheck.protocol.Scoring
import com.devcheck.protocol.Signal

/**
 * 阶段一的本地评分器（用服务端共享的 [Scoring] 权重与阻断点规则）。
 * 输出的 RiskReport 仅供本地参考 / 灰度 / 离线降级，不作为权威裁决。
 */
internal object LocalRiskScorer {
    fun build(signals: List<Signal>, elapsedMs: Long, nativeAvailable: Boolean): RiskReport {
        val r = Scoring.evaluate(signals)
        return RiskReport(
            verdict = r.verdict,
            score = r.score,
            signals = signals.sortedWith(
                compareByDescending<Signal> { Scoring.isBlocker(it) }
                    .thenByDescending { Scoring.weight(it.severity) },
            ),
            categoryScores = r.categoryScores,
            elapsedMs = elapsedMs,
            nativeAvailable = nativeAvailable,
            blockingSignals = r.blockingSignals,
        )
    }
}
