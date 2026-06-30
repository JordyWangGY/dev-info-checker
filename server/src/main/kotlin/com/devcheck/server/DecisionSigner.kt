package com.devcheck.server

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * 签发 / 验证 Decision JWT（ES256，阶段二批次一 2.3）。
 *
 * 用 EC P-256 + JDK 的 `SHA256withECDSAinP1363Format`（直接产出 JOSE 要求的定长 r||s 签名，
 * 无需 DER↔JOSE 转换）。**纯 JDK，无第三方依赖。** 业务后端用 [publicKey] 独立验签即可信任。
 */
class DecisionSigner(private val keyPair: KeyPair = generate()) {

    val publicKey: PublicKey get() = keyPair.public

    private val alg = "SHA256withECDSAinP1363Format"
    private val b64 = Base64.getUrlEncoder().withoutPadding()
    private val b64d = Base64.getUrlDecoder()

    /** payloadJson 为已序列化的 JWT claims。返回 `header.payload.signature`。 */
    fun sign(payloadJson: String): String {
        val header = """{"alg":"ES256","typ":"JWT"}"""
        val signingInput =
            "${b64.encodeToString(header.toByteArray())}.${b64.encodeToString(payloadJson.toByteArray())}"
        val sig = Signature.getInstance(alg).run {
            initSign(keyPair.private); update(signingInput.toByteArray()); sign()
        }
        return "$signingInput.${b64.encodeToString(sig)}"
    }

    fun verify(jwt: String, key: PublicKey = keyPair.public): Boolean = runCatching {
        val parts = jwt.split(".")
        if (parts.size != 3) return false
        Signature.getInstance(alg).run {
            initVerify(key)
            update("${parts[0]}.${parts[1]}".toByteArray())
            verify(b64d.decode(parts[2]))
        }
    }.getOrDefault(false)

    companion object {
        fun generate(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
    }
}
