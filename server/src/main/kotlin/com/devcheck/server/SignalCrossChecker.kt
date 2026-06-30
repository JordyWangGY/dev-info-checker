package com.devcheck.server

import com.devcheck.protocol.EvidenceBundle
import com.devcheck.protocol.Scoring
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Verdict
import kotlin.math.abs

/**
 * 服务端交叉校验（阶段二批次二，ARCHITECTURE §5.3「杀手锏」）。
 *
 * 客户端自报的 [EvidenceBundle] **明文可伪造**，这里用「自洽性 + 硬件真相」反向打假：
 * 找出互相矛盾之处，产出 [Finding] 交 [AuthoritativeScorer] 升级裁决。
 * 不依赖真机 / Google 凭证——纯逻辑，可单测。
 */
class SignalCrossChecker(
    /** 受信任的 Google GMS 签名 SHA-256（大写 hex）。空集=不做 GMS 签名比对。 */
    private val trustedGmsSig: Set<String> = emptySet(),
) {
    data class Finding(val id: String, val severity: Severity, val detail: String)

    private val armBrands = setOf("samsung", "google", "xiaomi", "redmi", "huawei", "honor", "oppo", "vivo", "oneplus", "motorola")

    fun check(
        bundle: EvidenceBundle,
        attest: KeyAttestationVerifier.Verdict,
    ): List<Finding> {
        val report = bundle.localReport
        val signals = report.signals
        fun ev(id: String, key: String): String? = signals.firstOrNull { it.id == id }?.evidence?.get(key)

        val out = ArrayList<Finding>()

        // 1) 说谎客户端：带了阻断点信号却自报 GENUINE
        if (signals.any { Scoring.isBlocker(it) } && report.verdict == Verdict.GENUINE) {
            out += Finding("xcheck.client_underreport", Severity.CRITICAL, "blocker present but client verdict=GENUINE")
        }

        // 2) 自报分与服务端重算分差距过大（客户端篡改了分数）
        val recomputed = Scoring.evaluate(signals).score
        if (abs(recomputed - report.score) >= 20) {
            out += Finding("xcheck.score_mismatch", Severity.HIGH, "client score=${report.score} vs recomputed=$recomputed")
        }

        // 3) Widevine L1（硬件 DRM）但 attestation 安全级别=SOFTWARE（无 TEE）——物理矛盾
        if (ev(Signals.FP_WIDEVINE, "securityLevel") == "L1" &&
            attest.present && attest.chainCryptoValid && attest.attestationSecurityLevel == 0
        ) {
            out += Finding("xcheck.widevine_vs_tee", Severity.HIGH, "Widevine L1 but attestation securityLevel=SOFTWARE")
        }

        // 4) 声称主流 ARM 机型却是 x86 ABI（模拟器/改机）
        val abis = ev(Signals.FP_ATTRIBUTES, "abis").orEmpty()
        val brand = ev(Signals.FP_ATTRIBUTES, "manufacturer").orEmpty().lowercase()
        if (abis.contains("x86") && armBrands.any { brand.contains(it) }) {
            out += Finding("xcheck.x86_on_arm_brand", Severity.HIGH, "x86 ABI on claimed brand=$brand")
        }

        // 5) GMS 签名与官方证书不符（microG/假 GMS）——仅在配置了受信任签名时比对
        val vendingSig = ev(Signals.ECOSYSTEM_INVENTORY, "vending_sig")?.uppercase()
        if (trustedGmsSig.isNotEmpty() && !vendingSig.isNullOrEmpty() && vendingSig !in trustedGmsSig) {
            out += Finding("xcheck.gms_sig_mismatch", Severity.HIGH, "vending signature not Google-official")
        }

        return out
    }
}
