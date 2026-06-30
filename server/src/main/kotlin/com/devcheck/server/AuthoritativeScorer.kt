package com.devcheck.server

import com.devcheck.protocol.EvidenceBundle
import com.devcheck.protocol.Scoring
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Verdict

/**
 * 权威评分（阶段二批次一 2.3 + 批次二交叉校验融合）。
 *
 * 原则：**不信客户端给的 verdict/score**——用共享的 [Scoring] 权重对端侧信号**重算**，
 * 再用服务端验过的**硬件真相**与[SignalCrossChecker]的**自洽性打假**升级裁决：
 *  - attestation 链可信且 securityLevel=SOFTWARE / challenge 不匹配 → COMPROMISED；
 *  - Play Integrity 判 MEETS_VIRTUAL_INTEGRITY → COMPROMISED；
 *  - 交叉校验出 CRITICAL 矛盾（如说谎客户端）→ COMPROMISED；其余按权重加分后重定级。
 */
class AuthoritativeScorer {

    data class Result(val verdict: Verdict, val score: Int, val reasons: List<String>)

    fun decide(
        bundle: EvidenceBundle,
        attest: KeyAttestationVerifier.Verdict,
        play: PlayIntegrityVerifier.Verdict,
        crossFindings: List<SignalCrossChecker.Finding> = emptyList(),
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

        // 3) 交叉校验融合：CRITICAL 矛盾直接 COMPROMISED；其余按 severity 权重加分后重定级
        crossFindings.forEach { reasons += "xcheck ${it.id}(${it.severity}): ${it.detail}" }
        if (crossFindings.any { it.severity == Severity.CRITICAL }) verdict = Verdict.COMPROMISED
        if (verdict != Verdict.COMPROMISED && crossFindings.isNotEmpty()) {
            score = minOf(Scoring.MAX_SCORE, score + crossFindings.sumOf { Scoring.weight(it.severity) })
            verdict = Scoring.verdict(score)
        }

        if (verdict == Verdict.COMPROMISED) score = 100
        return Result(verdict, score, reasons)
    }
}
