package com.devcheck.server

import com.devcheck.protocol.EvidenceBundle
import com.devcheck.protocol.Scoring
import com.devcheck.protocol.Verdict

/**
 * 权威评分（阶段二批次一 2.3）。
 *
 * 原则：**不信客户端给的 verdict/score**——用共享的 [Scoring] 权重对端侧信号**重算**，
 * 再用服务端验过的**硬件真相**硬覆盖：
 *  - attestation 链可信且 securityLevel=SOFTWARE / challenge 不匹配 → COMPROMISED；
 *  - Play Integrity 判 MEETS_VIRTUAL_INTEGRITY → COMPROMISED。
 */
class AuthoritativeScorer {

    data class Result(val verdict: Verdict, val score: Int, val reasons: List<String>)

    fun decide(
        bundle: EvidenceBundle,
        attest: KeyAttestationVerifier.Verdict,
        play: PlayIntegrityVerifier.Verdict,
    ): Result {
        val reasons = ArrayList<String>()

        // 1) 端侧信号按权威权重重算
        val local = Scoring.evaluate(bundle.localReport.signals)
        var verdict = local.verdict
        var score = local.score
        reasons += "local-rescore verdict=$verdict score=$score"

        // 2) 硬件真相硬覆盖（仅当链可信才据其下结论）
        if (attest.present && attest.chainCryptoValid && attest.rootTrusted) {
            if (attest.attestationSecurityLevel == 0) {
                verdict = Verdict.COMPROMISED; reasons += "attestation securityLevel=SOFTWARE"
            }
            if (!attest.challengeMatch) {
                verdict = Verdict.COMPROMISED; reasons += "attestation challenge mismatch (replay?)"
            }
        } else if (attest.present) {
            reasons += "attestation present but not authoritative: ${attest.reasons.joinToString()}"
        } else {
            reasons += "no attestation chain"
        }

        if (play.available && play.deviceVerdict == "MEETS_VIRTUAL_INTEGRITY") {
            verdict = Verdict.COMPROMISED; reasons += "play integrity: virtual device"
        } else if (!play.available) {
            reasons += "play integrity unavailable: ${play.reason}"
        }

        if (verdict == Verdict.COMPROMISED) score = 100
        return Result(verdict, score, reasons)
    }
}
