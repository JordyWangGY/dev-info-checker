package com.devcheck.server

/** Play Integrity 服务端验签（阶段二批次一 2.2a）。 */
interface PlayIntegrityVerifier {

    data class Verdict(
        val available: Boolean,
        /** MEETS_DEVICE_INTEGRITY / MEETS_BASIC_INTEGRITY / MEETS_VIRTUAL_INTEGRITY ... */
        val deviceVerdict: String? = null,
        val appVerdict: String? = null,
        val nonceMatch: Boolean = false,
        val reason: String? = null,
    )

    fun verify(token: String?, expectedNonce: String): Verdict
}

/**
 * 占位实现：真正解码需 **Google Play Integrity API 凭证**（Cloud 项目 + 服务账号，调
 * `playintegrity.googleapis.com` 的 `decodeIntegrityToken`）。此处**不伪造结论**，统一返回不可用，
 * 待接入凭证后替换为真实 verifier。
 */
class StubPlayIntegrityVerifier : PlayIntegrityVerifier {
    override fun verify(token: String?, expectedNonce: String) = PlayIntegrityVerifier.Verdict(
        available = false,
        reason = if (token == null) "no token" else "decode requires Google API credentials (not configured)",
    )
}
