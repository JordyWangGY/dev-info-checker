package com.devcheck.server

import com.devcheck.protocol.Category
import com.devcheck.protocol.EvidenceBundle
import com.devcheck.protocol.RiskReport
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import com.devcheck.protocol.Verdict
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AttestServiceTest {

    private fun bundle(nonce: String, source: String, signals: List<Signal>) = EvidenceBundle(
        nonce = nonce,
        nonceSource = source,
        localReport = RiskReport(verdict = Verdict.GENUINE, score = 0, signals = signals),
    )

    @Test
    fun rejectsLocalNonce() {
        val nonces = NonceService()
        val svc = AttestService(nonces)
        val out = svc.handle(bundle("whatever", "local", emptyList()))
        assertFalse(out.accepted)
    }

    @Test
    fun rejectsReplay() {
        val nonces = NonceService()
        val svc = AttestService(nonces)
        val n = nonces.issue()
        assertTrue(svc.handle(bundle(n, "server", emptyList())).accepted)   // 首次
        assertFalse(svc.handle(bundle(n, "server", emptyList())).accepted)  // 重放
    }

    @Test
    fun serverRescoresAndIgnoresClientClaimedVerdict() {
        val nonces = NonceService()
        val svc = AttestService(nonces)
        val n = nonces.issue()
        // 客户端「自称」GENUINE，但带了一个 NATIVE frida 阻断点信号 → 服务端重算应判 COMPROMISED
        val lying = listOf(Signal(Signals.HOOK_FRIDA_MAPS, Category.HOOK, Severity.HIGH, 1f, Source.NATIVE))
        val out = svc.handle(bundle(n, "server", lying))

        assertTrue(out.accepted)
        assertEquals(Verdict.COMPROMISED.name, out.verdict)
        assertEquals(100, out.score)
        assertNotNull(out.decisionJwt)
        assertTrue(svc.signer.verify(out.decisionJwt!!)) // 决策令牌可验签
    }
}
