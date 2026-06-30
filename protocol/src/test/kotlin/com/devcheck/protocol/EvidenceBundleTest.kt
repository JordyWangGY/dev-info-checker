package com.devcheck.protocol

import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class EvidenceBundleTest {

    @Test
    fun roundTripsThroughJson() {
        val report = RiskReport(
            verdict = Verdict.GENUINE,
            score = 0,
            signals = listOf(Signal(Signals.FP_ATTRIBUTES, Category.FINGERPRINT, Severity.INFO)),
        )
        val bundle = EvidenceBundle(
            nonce = "abc123",
            nonceSource = "local",
            playIntegrityToken = "token.xyz",
            keyAttestationChainDerB64 = listOf("LEAFDER", "ROOTDER"),
            localReport = report,
        )
        val json = Json { ignoreUnknownKeys = true }
        val encoded = json.encodeToString(EvidenceBundle.serializer(), bundle)
        val decoded = json.decodeFromString(EvidenceBundle.serializer(), encoded)

        assertEquals(bundle, decoded)
        assertEquals("local", decoded.nonceSource)
        assertEquals(2, decoded.keyAttestationChainDerB64.size)
        assertEquals(Verdict.GENUINE, decoded.localReport.verdict)
    }
}
