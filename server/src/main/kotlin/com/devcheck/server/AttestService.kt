package com.devcheck.server

import com.devcheck.protocol.EvidenceBundle
import kotlinx.serialization.Serializable

/**
 * 阶段二验证流水线编排（批次一 2.1–2.3）：
 *  消费 nonce（必须服务端签发、单次）→ 验 attestation 链 → 验 Play Integrity →
 *  权威评分 → 签发 Decision JWT。
 */
class AttestService(
    private val nonces: NonceService,
    private val attestVerifier: KeyAttestationVerifier = KeyAttestationVerifier(),
    private val playVerifier: PlayIntegrityVerifier = StubPlayIntegrityVerifier(),
    private val crossChecker: SignalCrossChecker = SignalCrossChecker(),
    private val scorer: AuthoritativeScorer = AuthoritativeScorer(),
    val signer: DecisionSigner = DecisionSigner(),
) {
    @Serializable
    data class Outcome(
        val accepted: Boolean,
        val verdict: String,
        val score: Int,
        val decisionJwt: String? = null,
        val reasons: List<String> = emptyList(),
    )

    fun handle(bundle: EvidenceBundle, now: Long = System.currentTimeMillis()): Outcome {
        // nonce 必须服务端签发且单次（本地兜底的 nonce 不可信，直接拒）
        if (bundle.nonceSource != "server" || !nonces.consume(bundle.nonce, now)) {
            return Outcome(false, "UNKNOWN", 0, null, listOf("nonce invalid / replayed / not server-issued"))
        }
        // 约定：attestation challenge = nonce 字符串的 UTF-8 字节（与客户端 AttestDetector 一致）
        val challenge = bundle.nonce.toByteArray()
        val attest = attestVerifier.verify(bundle.keyAttestationChainDerB64, challenge)
        val play = playVerifier.verify(bundle.playIntegrityToken, bundle.nonce)
        val cross = crossChecker.check(bundle, attest)
        val decision = scorer.decide(bundle, attest, play, cross)

        val payload = """{"verdict":"${decision.verdict}","score":${decision.score},""" +
            """"nonce":"${bundle.nonce}","iat":$now}"""
        return Outcome(true, decision.verdict.name, decision.score, signer.sign(payload), decision.reasons)
    }
}
