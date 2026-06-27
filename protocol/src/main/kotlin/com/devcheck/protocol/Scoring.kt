package com.devcheck.protocol

/**
 * 评分模型（客户端与服务端共用同一套权重，保证三端一致）。
 *
 * 两条并行的判定路径：
 *  1. **阻断点硬覆盖**：只要命中任一 [isBlocker] 信号 → 直接 score=100、verdict=COMPROMISED，
 *     列出所有命中的阻断点（dispositive，100% 不可信）。
 *  2. **加权评分**：无阻断点时，按类别分组 Σ(severityWeight × confidence)，单类封顶 [CATEGORY_CAP]，
 *     各类之和封顶 [MAX_SCORE]，再按阈值映射到 [Verdict]。
 */
object Scoring {
    const val CATEGORY_CAP = 70
    const val MAX_SCORE = 100

    fun weight(sev: Severity): Int = when (sev) {
        Severity.INFO -> 0
        Severity.LOW -> 5
        Severity.MEDIUM -> 15
        Severity.HIGH -> 35
        Severity.CRITICAL -> 60
    }

    /**
     * 是否为阻断点：① 显式 `blocking=true`；或 ② 在 [Blockers.IDS] 名录中且来源可信(NATIVE/HARDWARE)。
     * 纯 Java 来源的同名信号只计分、不阻断（Java 层可被 hook 伪造，不足以 100%）。
     */
    fun isBlocker(s: Signal): Boolean =
        s.blocking || (s.id in Blockers.IDS && (s.source == Source.NATIVE || s.source == Source.HARDWARE))

    data class Result(
        val score: Int,
        val verdict: Verdict,
        val categoryScores: Map<Category, Int>,
        val blockingSignals: List<Signal>,
    )

    fun evaluate(signals: List<Signal>, evaluated: Boolean = true): Result {
        if (!evaluated) return Result(0, Verdict.UNKNOWN, emptyMap(), emptyList())

        val perCat = signals
            .groupBy { it.category }
            .mapValues { (_, list) ->
                val sum = list.sumOf { (weight(it.severity) * it.confidence).toDouble() }
                minOf(CATEGORY_CAP.toDouble(), sum).toInt()
            }
            .filterValues { it > 0 }

        val blockers = signals.filter { isBlocker(it) }
        if (blockers.isNotEmpty()) {
            return Result(MAX_SCORE, Verdict.COMPROMISED, perCat, blockers)
        }
        val total = minOf(MAX_SCORE, perCat.values.sum())
        return Result(total, verdict(total), perCat, emptyList())
    }

    fun verdict(score: Int): Verdict = when {
        score < 20 -> Verdict.GENUINE
        score < 40 -> Verdict.LOW_RISK
        score < 70 -> Verdict.SUSPICIOUS
        score < 90 -> Verdict.HIGH_RISK
        else -> Verdict.COMPROMISED
    }
}
