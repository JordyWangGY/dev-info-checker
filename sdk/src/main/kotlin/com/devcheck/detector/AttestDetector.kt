package com.devcheck.detector

import android.util.Base64
import com.devcheck.attest.KeyAttestation
import com.devcheck.attest.PlayIntegrity
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.SecureRandom

/**
 * 硬件背书检测（阶段一 1.3：客户端采集 + 本地解析）。
 *
 * Key Attestation：生成硬件密钥并解析证书链 attestation 扩展，读取
 * securityLevel / verifiedBootState / deviceLocked，命中即触发 **HARDWARE 来源阻断点**：
 *  - SOFTWARE 安全级别 → `attest.key.not_hardware`（无真实 TEE）
 *  - verifiedBootState 非 Verified 或 deviceLocked=false → `attest.key.verified_boot_fail`
 */
internal class AttestDetector : Detector {
    override val id = "attest"
    override val category = Category.ATTEST
    override val timeoutMs: Long? = 8000L // 硬件密钥生成可能较慢

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()

        val challenge = ByteArray(24).also { SecureRandom().nextBytes(it) }
        val r = KeyAttestation.attest(challenge)

        if (!r.available) {
            // 拿不到硬件 attestation（部分模拟器/老设备）。不直接阻断（避免误报），记可疑信号。
            out += Signal(
                Signals.ATTEST_KEY_CHAIN, category, Severity.MEDIUM, 0.5f, Source.JAVA,
                mapOf("available" to "false", "reason" to (r.error ?: "")),
            )
            return@withContext out
        }

        out += Signal(
            Signals.ATTEST_KEY_CHAIN, category, Severity.INFO, 1f, Source.HARDWARE,
            mapOf(
                "securityLevel" to r.securityLevel.name,
                "verifiedBootState" to r.bootState.name,
                "deviceLocked" to r.deviceLocked.toString(),
                "strongBox" to r.strongBox.toString(),
                "chainLen" to r.chainLength.toString(),
            ),
        )

        // 阻断点 #7：无真实 TEE
        if (r.securityLevel == KeyAttestation.SecurityLevel.SOFTWARE) {
            out += Signal(
                Signals.ATTEST_KEY_NOT_HARDWARE, category, Severity.CRITICAL, 1f, Source.HARDWARE,
                mapOf("securityLevel" to r.securityLevel.name),
            )
        }

        // 阻断点 #6：引导链未通过验证 / bootloader 解锁
        val bootBad = r.bootState == KeyAttestation.BootState.SELF_SIGNED ||
            r.bootState == KeyAttestation.BootState.UNVERIFIED ||
            r.bootState == KeyAttestation.BootState.FAILED
        if (bootBad || r.deviceLocked == false) {
            out += Signal(
                Signals.ATTEST_KEY_VERIFIED_BOOT_FAIL, category, Severity.CRITICAL, 1f, Source.HARDWARE,
                mapOf("verifiedBootState" to r.bootState.name, "deviceLocked" to r.deviceLocked.toString()),
            )
        }

        // Play Integrity：仅在配置了 cloudProjectNumber（有 GMS 场景）时采集令牌，验签留待阶段二
        ctx.config.playIntegrityCloudProjectNumber?.let { proj ->
            val nonce = Base64.encodeToString(challenge, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            val pi = PlayIntegrity.request(ctx.app, proj, nonce)
            out += Signal(
                Signals.ATTEST_PLAY_INTEGRITY, category, Severity.INFO, 1f,
                if (pi.available) Source.HARDWARE else Source.JAVA,
                mapOf(
                    "available" to pi.available.toString(),
                    "token_len" to (pi.token?.length ?: 0).toString(),
                    "reason" to (pi.error ?: ""),
                ),
            )
        }

        out
    }
}
