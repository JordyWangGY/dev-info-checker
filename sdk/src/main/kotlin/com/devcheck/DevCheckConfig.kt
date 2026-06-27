package com.devcheck

import com.devcheck.protocol.Category

/**
 * SDK 配置。阶段一只用到本地检测相关字段；标注「阶段二」的字段当前未生效。
 */
data class DevCheckConfig(
    /** 阶段二：风控服务端地址。阶段一可为 null（纯本地）。 */
    val serverBaseUrl: String? = null,

    /** Tamper 检测用：宿主 App 发布签名证书的 SHA-256（大写十六进制、去冒号）。null 则跳过签名校验。 */
    val expectedSignatureSha256: String? = null,

    /** 有 GMS 时填入 Google Cloud 项目编号以启用 Play Integrity（阶段二服务端验签）。 */
    val playIntegrityCloudProjectNumber: Long? = null,

    /** 启用的检测类别，默认全开。 */
    val enabledCategories: Set<Category> = Category.entries.toSet(),

    /** 单个 Detector 的超时（毫秒）；超时按 fail-closed 记一条 MEDIUM 信号。 */
    val perDetectorTimeoutMs: Long = 1500,

    /** 是否输出调试日志。 */
    val debugLogging: Boolean = false,
)
