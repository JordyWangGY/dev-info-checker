package com.devcheck.detector

import android.util.Base64
import com.devcheck.attest.KeyAttestation
import com.devcheck.attest.PlayIntegrity
import com.google.android.play.core.integrity.model.IntegrityErrorCode as EC
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

        // nonce 优先用服务端下发的（DevCheck 解析后经 ctx 传入）；为空则本地兜底。
        val nonceStr = ctx.nonceB64.ifEmpty {
            Base64.encodeToString(
                ByteArray(24).also { SecureRandom().nextBytes(it) },
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
            )
        }
        val r = KeyAttestation.attest(nonceStr.toByteArray())
        ctx.sink.attestationChainDerB64 = r.chainDerB64 // 原始链交 DevCheck 组装上报包（不入 signal 明文）

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
            val pi = PlayIntegrity.request(ctx.app, proj, nonceStr)
            ctx.sink.playIntegrityToken = pi.token // 令牌原文交 DevCheck 组装上报包（不入 signal 明文）
            out += Signal(
                Signals.ATTEST_PLAY_INTEGRITY, category, Severity.INFO, 1f,
                if (pi.available) Source.HARDWARE else Source.JAVA,
                mapOf(
                    "available" to pi.available.toString(),
                    "token_len" to (pi.token?.length ?: 0).toString(),
                    "reason" to (pi.error ?: ""),
                ),
            )
            // 令牌请求失败时，确定性错误码本地即暴露 GMS/Play 环境真伪（无需解码）→ 计分。
            // 瞬时/网络/配置类错误一律忽略，避免误报；去谷歌真机的「无 GMS」属同类误报，故仅计分非阻断。
            if (!pi.available) playEnvSignal(pi.errorCode)?.let { out += it }
        }

        out
    }

    /** 把确定性的 Play Integrity 错误码映射为计分信号；瞬时/未知码返回 null（不计分）。 */
    private fun playEnvSignal(code: Int): Signal? {
        val (sev, conf) = when (code) {
            // 安装上下文被篡改（多开 / 重打包的强迹象）
            EC.APP_UID_MISMATCH, EC.APP_NOT_INSTALLED -> Severity.HIGH to 0.7f
            // 无正版 GMS/Play，或 Integrity 服务无法绑定（模拟器 / AOSP / microG / 伪造 GMS）
            EC.PLAY_SERVICES_NOT_FOUND, EC.PLAY_STORE_NOT_FOUND,
            EC.CANNOT_BIND_TO_SERVICE, EC.API_NOT_AVAILABLE -> Severity.MEDIUM to 0.5f
            // 版本异常旧 / 无 Google 账号（弱信号，真机也可能）
            EC.PLAY_SERVICES_VERSION_OUTDATED, EC.PLAY_STORE_VERSION_OUTDATED,
            EC.PLAY_STORE_ACCOUNT_NOT_FOUND -> Severity.LOW to 0.5f
            // NETWORK_ERROR / TOO_MANY_REQUESTS / GOOGLE_SERVER_UNAVAILABLE / CLIENT_TRANSIENT_ERROR /
            // INTERNAL_ERROR / NONCE_* / CLOUD_PROJECT_NUMBER_IS_INVALID / NO_ERROR / 未知 → 忽略
            else -> return null
        }
        return Signal(
            Signals.ATTEST_PLAY_ENV, category, sev, conf, Source.JAVA,
            mapOf("errorCode" to code.toString(), "name" to ecName(code)),
        )
    }

    private fun ecName(code: Int): String = when (code) {
        EC.APP_UID_MISMATCH -> "APP_UID_MISMATCH"
        EC.APP_NOT_INSTALLED -> "APP_NOT_INSTALLED"
        EC.PLAY_SERVICES_NOT_FOUND -> "PLAY_SERVICES_NOT_FOUND"
        EC.PLAY_STORE_NOT_FOUND -> "PLAY_STORE_NOT_FOUND"
        EC.CANNOT_BIND_TO_SERVICE -> "CANNOT_BIND_TO_SERVICE"
        EC.API_NOT_AVAILABLE -> "API_NOT_AVAILABLE"
        EC.PLAY_SERVICES_VERSION_OUTDATED -> "PLAY_SERVICES_VERSION_OUTDATED"
        EC.PLAY_STORE_VERSION_OUTDATED -> "PLAY_STORE_VERSION_OUTDATED"
        EC.PLAY_STORE_ACCOUNT_NOT_FOUND -> "PLAY_STORE_ACCOUNT_NOT_FOUND"
        else -> "OTHER"
    }
}
