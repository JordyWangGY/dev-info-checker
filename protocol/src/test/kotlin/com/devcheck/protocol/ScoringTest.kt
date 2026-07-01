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
        assertEquals(Verdict.COMPROMISED, r.verdict)   // 阻断点硬覆盖裁决
        assertEquals(0, r.score)                       // 但评分与阻断点分开：阻断信号不计入分数
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
    fun newEcosystemAndFileTimeSignalsScoreButNeverBlock() {
        // 新增信号均非阻断点：不在 Blockers.IDS，且即便命中也不得强判 COMPROMISED
        val newIds = listOf(
            Signals.ECOSYSTEM_BRAND_MISMATCH, Signals.ECOSYSTEM_NO_GMS, Signals.ECOSYSTEM_INVENTORY,
            Signals.FILETIME_INSTALL_BEFORE_BUILD, Signals.FILETIME_UNIFORM_INSTALL,
            Signals.FILETIME_FUTURE_FILE, Signals.FILETIME_CRTIME,
        )
        newIds.forEach { assertFalse(it in Blockers.IDS, "$it 不应是阻断点") }
        // Play Integrity 错误码环境信号同样仅计分、非阻断（去谷歌真机会合法触发）
        assertFalse(Signals.ATTEST_PLAY_ENV in Blockers.IDS)
        val pe = Scoring.evaluate(listOf(sig(Signals.ATTEST_PLAY_ENV, Category.ATTEST, Severity.MEDIUM)))
        assertTrue(pe.blockingSignals.isEmpty())
        assertFalse(pe.verdict == Verdict.COMPROMISED)

        // SELinux/上下文信号同样仅计分、非阻断（rooted 真机 setenforce 0 也会 permissive）
        listOf(
            Signals.EMULATOR_SELINUX_PERMISSIVE, Signals.EMULATOR_SELINUX_CONTEXT,
            Signals.EMULATOR_SELINUX_FS, Signals.EMULATOR_SELINUX_INFO,
        ).forEach { assertFalse(it in Blockers.IDS, "$it 不应是阻断点") }

        // 云手机检测信号同样仅计分、非阻断（ARM 云机上单条可被伪造）
        listOf(
            Signals.CLOUD_KERNEL, Signals.CLOUD_DISK, Signals.CLOUD_PCI, Signals.CLOUD_INPUT,
            Signals.CLOUD_CGROUP, Signals.CLOUD_NET, Signals.CLOUD_NO_BATTERY,
            Signals.CLOUD_SOUNDCARD, Signals.CLOUD_VM_FIRMWARE, Signals.CLOUD_SENSOR_VENDOR,
            Signals.CLOUD_VIRTIO, Signals.CLOUD_INFO,
        ).forEach { assertFalse(it in Blockers.IDS, "$it 不应是阻断点") }

        // 单独一个品牌不符(HIGH) 远不到 COMPROMISED
        val r = Scoring.evaluate(listOf(sig(Signals.ECOSYSTEM_BRAND_MISMATCH, Category.EMULATOR, Severity.HIGH)))
        assertTrue(r.blockingSignals.isEmpty())
        assertFalse(r.verdict == Verdict.COMPROMISED)
    }

    @Test
    fun ecosystemSignalsShareEmulatorCategoryCap() {
        // ecosystem.* 归入 EMULATOR 类，与既有 emulator 信号共享 70 封顶，不独占评分预算
        val signals = listOf(
            sig(Signals.EMULATOR_BUILD_PROPS, Category.EMULATOR, Severity.HIGH),
            sig(Signals.ECOSYSTEM_BRAND_MISMATCH, Category.EMULATOR, Severity.HIGH),
            sig(Signals.ECOSYSTEM_NO_GMS, Category.EMULATOR, Severity.HIGH),
        )
        assertTrue((Scoring.evaluate(signals).categoryScores[Category.EMULATOR] ?: 0) <= 70)
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
