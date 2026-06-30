package com.devcheck.server

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Key Attestation 服务端验签（阶段二批次一 2.2b）。
 *
 * 把客户端 [EvidenceBundle.keyAttestationChainDerB64] 的证书链：
 *  1. 做密码学链验证（逐级验签 + 根自签）；
 *  2. 比对根证书到**受信任的 Google 硬件 attestation 根**（未配置则老实标 rootTrusted=false）；
 *  3. 校验叶证书 attestation 扩展里的 challenge == 服务端 nonce（防重放绑定）；
 *  4. 读 attestationSecurityLevel（0=SOFTWARE/1=TEE/2=STRONGBOX）。
 *
 * 注：完整的 verifiedBootState/rootOfTrust 深层解析为后续项；当前覆盖 challenge + securityLevel。
 */
class KeyAttestationVerifier(
    /** 受信任的 Google 硬件根证书 SHA-256（大写 hex）。空集=未配置，rootTrusted 恒 false。 */
    private val trustedRootSha256: Set<String> = emptySet(),
) {
    private val oid = "1.3.6.1.4.1.11129.2.1.17"

    data class Verdict(
        val present: Boolean,
        val chainCryptoValid: Boolean = false,
        val rootTrusted: Boolean = false,
        val challengeMatch: Boolean = false,
        val attestationSecurityLevel: Int = -1,
        val chainLen: Int = 0,
        val reasons: List<String> = emptyList(),
    )

    fun verify(chainDerB64: List<String>, expectedChallenge: ByteArray): Verdict {
        if (chainDerB64.isEmpty()) return Verdict(false, reasons = listOf("empty chain"))
        val reasons = ArrayList<String>()
        val cf = CertificateFactory.getInstance("X.509")
        val certs = chainDerB64.map {
            cf.generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode(it))) as X509Certificate
        }

        // 1) 链密码学有效性
        var chainValid = true
        for (i in 0 until certs.size - 1) {
            val ok = runCatching { certs[i].verify(certs[i + 1].publicKey); true }.getOrDefault(false)
            if (!ok) { chainValid = false; reasons += "cert[$i] not signed by cert[${i + 1}]" }
        }
        val root = certs.last()
        if (!runCatching { root.verify(root.publicKey); true }.getOrDefault(false)) {
            chainValid = false; reasons += "root not self-signed"
        }

        // 2) 根固定
        val rootTrusted = when {
            trustedRootSha256.isEmpty() -> { reasons += "no pinned Google root configured"; false }
            sha256Hex(root.encoded) in trustedRootSha256 -> true
            else -> { reasons += "root sha not in trusted set"; false }
        }

        // 3) challenge == nonce
        val leaf = certs.first()
        val ext = leaf.getExtensionValue(oid)
        val challengeMatch = ext != null &&
            extractChallenge(ext)?.contentEquals(expectedChallenge) == true
        if (!challengeMatch) reasons += "attestation challenge != nonce"

        // 4) securityLevel
        val secLevel = ext?.let { extractSecurityLevel(it) } ?: -1

        return Verdict(true, chainValid, rootTrusted, challengeMatch, secLevel, certs.size, reasons)
    }

    private fun extractChallenge(ext: ByteArray): ByteArray? {
        val (data, seq) = keyDescription(ext) ?: return null
        val fields = Der.children(data, seq)
        return if (fields.size >= 5) Der.content(data, fields[4]) else null
    }

    private fun extractSecurityLevel(ext: ByteArray): Int {
        val (data, seq) = keyDescription(ext) ?: return -1
        val fields = Der.children(data, seq)
        return if (fields.size >= 2) Der.intValue(data, fields[1]) else -1
    }

    /** 扩展值外层是 OCTET STRING，内容才是 KeyDescription SEQUENCE。 */
    private fun keyDescription(ext: ByteArray): Pair<ByteArray, Der.TLV>? {
        val outer = Der.parse(ext, 0)
        if (outer.tag != Der.OCTET_STRING) return null
        val inner = Der.content(ext, outer)
        val seq = Der.parse(inner, 0)
        if (seq.tag != Der.SEQUENCE) return null
        return inner to seq
    }

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02X".format(it) }
}
