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

        // 6) 云手机/容器：客户端把 cloud_info 采集为 INFO(0 分)，但其证据里藏着铁证。
        //    真机绝不会「自证」是 QEMU/generic 内核，故这里据采集证据服务端重判：
        val fw = ev(Signals.CLOUD_INFO, "firmware").orEmpty().lowercase()
        val osv = ev(Signals.CLOUD_INFO, "os_version").orEmpty().lowercase()
        if (fw.contains("qemu_fw_cfg") || osv.contains("generic") || osv.contains("ubuntu") || osv.contains("-lv")) {
            out += Finding("xcheck.cloud_vm_selfid", Severity.CRITICAL,
                "VM/容器自曝: firmware=$fw os_version=$osv（真机不可能出现）")
        }
        // 云机指标叠加：多个 emulator.cloud_* 命中 = 强环境证据（单条可能边缘误报，故要求计数）
        val cloudHits = signals.count { it.id.startsWith("emulator.cloud_") && it.severity != Severity.INFO }
        if (cloudHits >= 3) {
            out += Finding("xcheck.cloud_environment", Severity.HIGH, "$cloudHits 个云手机/容器指标命中")
        }

        return out
    }
}
