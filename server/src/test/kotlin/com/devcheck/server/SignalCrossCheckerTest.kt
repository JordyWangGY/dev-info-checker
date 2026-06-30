package com.devcheck.server

import com.devcheck.protocol.Category
import com.devcheck.protocol.EvidenceBundle
import com.devcheck.protocol.RiskReport
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import com.devcheck.protocol.Verdict
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SignalCrossCheckerTest {

    private val noAttest = KeyAttestationVerifier.Verdict(present = false)

    private fun bundle(verdict: Verdict, score: Int, signals: List<Signal>) = EvidenceBundle(
        nonce = "n", nonceSource = "server",
        localReport = RiskReport(verdict = verdict, score = score, signals = signals),
    )

    @Test
    fun flagsLyingClient() {
        // 带 NATIVE frida 阻断信号却自报 GENUINE
        val signals = listOf(Signal(Signals.HOOK_FRIDA_MAPS, Category.HOOK, Severity.HIGH, 1f, Source.NATIVE))
        val findings = SignalCrossChecker().check(bundle(Verdict.GENUINE, 0, signals), noAttest)
        assertTrue(findings.any { it.id == "xcheck.client_underreport" && it.severity == Severity.CRITICAL })
    }

    @Test
    fun flagsX86OnArmBrand() {
        val signals = listOf(
            Signal(Signals.FP_ATTRIBUTES, Category.FINGERPRINT, Severity.INFO, 1f, Source.JAVA,
                mapOf("manufacturer" to "samsung", "abis" to "x86_64,x86")),
        )
        val findings = SignalCrossChecker().check(bundle(Verdict.GENUINE, 0, signals), noAttest)
        assertTrue(findings.any { it.id == "xcheck.x86_on_arm_brand" })
    }

    @Test
    fun flagsWidevineVsSoftwareTee() {
        val signals = listOf(
            Signal(Signals.FP_WIDEVINE, Category.FINGERPRINT, Severity.INFO, 1f, Source.HARDWARE,
                mapOf("securityLevel" to "L1")),
        )
        val attestSoftware = KeyAttestationVerifier.Verdict(
            present = true, chainCryptoValid = true, attestationSecurityLevel = 0,
        )
        val findings = SignalCrossChecker().check(bundle(Verdict.GENUINE, 0, signals), attestSoftware)
        assertTrue(findings.any { it.id == "xcheck.widevine_vs_tee" })
    }

    @Test
    fun cleanConsistentReportHasNoFindings() {
        val signals = listOf(
            Signal(Signals.FP_ATTRIBUTES, Category.FINGERPRINT, Severity.INFO, 1f, Source.JAVA,
                mapOf("manufacturer" to "samsung", "abis" to "arm64-v8a")),
        )
        val findings = SignalCrossChecker().check(bundle(Verdict.GENUINE, 0, signals), noAttest)
        assertFalse(findings.isNotEmpty())
    }
}
