package com.devcheck.attest

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * Android Key Attestation（硬件背书）。
 *
 * 生成一枚硬件支持的 EC 密钥（StrongBox 优先，回退 TEE），把 server/random challenge 绑进证书，
 * 然后**本地解析**证书链叶子里的 attestation 扩展，读取：
 *  - attestationSecurityLevel（Software / TEE / StrongBox）
 *  - RootOfTrust.verifiedBootState（Verified=GREEN / SelfSigned / Unverified / Failed）
 *  - RootOfTrust.deviceLocked
 *
 * 注意：本地仅读取「硬件已签名证书」中的字段；证书链是否回溯 Google 硬件根 CA、是否吊销，
 * 这类**权威校验在阶段二服务端**完成（届时整条链上送）。
 */
internal object KeyAttestation {

    private const val ALIAS = "devcheck_attest_key"
    private const val OID = "1.3.6.1.4.1.11129.2.1.17"

    enum class SecurityLevel { SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX, UNKNOWN }
    enum class BootState { VERIFIED, SELF_SIGNED, UNVERIFIED, FAILED, UNKNOWN }

    data class Result(
        val available: Boolean,
        val securityLevel: SecurityLevel = SecurityLevel.UNKNOWN,
        val bootState: BootState = BootState.UNKNOWN,
        val deviceLocked: Boolean? = null,
        val chainLength: Int = 0,
        val strongBox: Boolean = false,
        val error: String? = null,
        /** 原始证书链 Base64(NO_WRAP) DER，leaf→root；交服务端验链到 Google 硬件根 CA（阶段二）。 */
        val chainDerB64: List<String> = emptyList(),
    )

    private class Chain(val certs: Array<Certificate>, val strongBox: Boolean)

    fun attest(challenge: ByteArray): Result = try {
        val chain = generateChain(challenge)
        val chainB64 = chain.certs.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }
        val leaf = chain.certs.firstOrNull() as? X509Certificate
            ?: return Result(false, error = "no leaf certificate", chainDerB64 = chainB64)
        val ext = leaf.getExtensionValue(OID)
            ?: return Result(false, chainLength = chain.certs.size, strongBox = chain.strongBox, error = "no attestation extension", chainDerB64 = chainB64)
        parseExtension(ext, chain.certs.size, chain.strongBox).copy(chainDerB64 = chainB64)
    } catch (t: Throwable) {
        Result(false, error = "${t.javaClass.simpleName}:${t.message ?: ""}")
    }

    private fun generateChain(challenge: ByteArray): Chain {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        runCatching { ks.deleteEntry(ALIAS) }

        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val strongBox = try {
            kpg.initialize(spec(strongBox = true)); kpg.generateKeyPair(); true
        } catch (e: StrongBoxUnavailableException) {
            kpg.initialize(spec(strongBox = false)); kpg.generateKeyPair(); false
        }
        return Chain(ks.getCertificateChain(ALIAS) ?: emptyArray(), strongBox)
    }

    /** extDer：扩展值（OCTET STRING 包裹 KeyDescription SEQUENCE）。 */
    private fun parseExtension(extDer: ByteArray, chainLen: Int, strongBox: Boolean): Result {
        val octet = Asn1.parse(extDer, 0)
        val keyDesc = Asn1.parse(extDer, octet.contentOffset)
        val fields = Asn1.children(extDer, keyDesc)

        // [1] attestationSecurityLevel ENUMERATED
        val secLevel = when (Asn1.intValue(extDer, fields[1])) {
            0 -> SecurityLevel.SOFTWARE
            1 -> SecurityLevel.TRUSTED_ENVIRONMENT
            2 -> SecurityLevel.STRONGBOX
            else -> SecurityLevel.UNKNOWN
        }

        // 末两个字段为 softwareEnforced / teeEnforced（AuthorizationList）
        var bootState = BootState.UNKNOWN
        var deviceLocked: Boolean? = null
        for (al in listOf(fields[fields.size - 1], fields[fields.size - 2])) {
            val rot = Asn1.children(extDer, al).firstOrNull { it.tag == Asn1.TAG_ROOT_OF_TRUST } ?: continue
            val rotSeq = Asn1.parse(extDer, rot.contentOffset) // [704] EXPLICIT → 内部 RootOfTrust SEQUENCE
            val rc = Asn1.children(extDer, rotSeq)
            // [0] verifiedBootKey OCTET, [1] deviceLocked BOOLEAN, [2] verifiedBootState ENUMERATED
            deviceLocked = Asn1.boolValue(extDer, rc[1])
            bootState = when (Asn1.intValue(extDer, rc[2])) {
                0 -> BootState.VERIFIED
                1 -> BootState.SELF_SIGNED
                2 -> BootState.UNVERIFIED
                3 -> BootState.FAILED
                else -> BootState.UNKNOWN
            }
            break
        }

        return Result(
            available = true,
            securityLevel = secLevel,
            bootState = bootState,
            deviceLocked = deviceLocked,
            chainLength = chainLen,
            strongBox = strongBox,
        )
    }
}
