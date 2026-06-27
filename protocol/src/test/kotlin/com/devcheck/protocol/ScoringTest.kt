package com.devcheck.protocol

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ScoringTest {

    private fun sig(
        id: String,
        cat: Category,
        sev: Severity,
        src: Source = Source.JAVA,
        blocking: Boolean = false,
    ) = Signal(id, cat, sev, 1f, src, emptyMap(), blocking)

    @Test
    fun cleanEnvIsGenuine() {
        val r = Scoring.evaluate(emptyList())
        assertEquals(Verdict.GENUINE, r.verdict)
        assertEquals(0, r.score)
        assertTrue(r.blockingSignals.isEmpty())
    }

    @Test
    fun nativeFridaMapsTriggersBlocker() {
        val r = Scoring.evaluate(listOf(sig(Signals.HOOK_FRIDA_MAPS, Category.HOOK, Severity.HIGH, Source.NATIVE)))
        assertEquals(Verdict.COMPROMISED, r.verdict)
        assertEquals(100, r.score)
        assertEquals(1, r.blockingSignals.size)
    }

    @Test
    fun javaFridaMapsIsScoredButNotBlocking() {
        // 同名信号但来源 JAVA（可被 hook 伪造）→ 只计分，不构成 100% 阻断
        val r = Scoring.evaluate(listOf(sig(Signals.HOOK_FRIDA_MAPS, Category.HOOK, Severity.HIGH, Source.JAVA)))
        assertTrue(r.blockingSignals.isEmpty())
        assertFalse(r.verdict == Verdict.COMPROMISED)
        assertEquals(35, r.score) // HIGH 权重=35
    }

    @Test
    fun explicitBlockingFlagForcesCompromised() {
        val r = Scoring.evaluate(listOf(sig("custom.x", Category.RUNTIME, Severity.LOW, blocking = true)))
        assertEquals(Verdict.COMPROMISED, r.verdict)
    }

    @Test
    fun categoryCapPreventsScoreStacking() {
        // 5 个 HIGH(35) 同类 → 原始 175，单类封顶到 70
        val many = (1..5).map { sig("root.x$it", Category.ROOT, Severity.HIGH) }
        assertEquals(70, Scoring.evaluate(many).categoryScores[Category.ROOT])
    }

    @Test
    fun detectionIsExhaustiveEvenWhenBlocked() {
        // 命中阻断点后，其它证据仍保留在分类分中（继续检测、不丢证据）
        val r = Scoring.evaluate(
            listOf(
                sig(Signals.EMULATOR_QEMU_PIPE, Category.EMULATOR, Severity.CRITICAL, Source.NATIVE),
                sig(Signals.NETWORK_VPN, Category.NETWORK, Severity.LOW),
            ),
        )
        assertEquals(Verdict.COMPROMISED, r.verdict)
        assertTrue(r.categoryScores.containsKey(Category.NETWORK))
    }

    @Test
    fun verdictThresholds() {
        assertEquals(Verdict.GENUINE, Scoring.verdict(10))
        assertEquals(Verdict.LOW_RISK, Scoring.verdict(30))
        assertEquals(Verdict.SUSPICIOUS, Scoring.verdict(55))
        assertEquals(Verdict.HIGH_RISK, Scoring.verdict(80))
        assertEquals(Verdict.COMPROMISED, Scoring.verdict(95))
    }
}
