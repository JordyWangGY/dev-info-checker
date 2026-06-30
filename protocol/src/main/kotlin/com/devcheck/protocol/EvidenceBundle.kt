package com.devcheck.protocol

import kotlinx.serialization.Serializable

/**
 * 阶段二上报包（客户端 → 服务端 `/v1/attest` 的契约，客户端与服务端共用此 DTO）。
 *
 * 信任锚是 [playIntegrityToken] 与 [keyAttestationChainDerB64]——只有它们能在服务端被
 * 权威验签；[localReport] 仅作参考（明文可伪造）。详见 `PHASE2_SERVER.md` §4。
 *
 * 注：`instanceSignature`（用 app 实例硬件密钥对 bundle 签名）属 §5 后续项，待实例密钥
 * 管理设计后再加；当前先打通「令牌 + 证书链 + nonce + 本地报告」的数据形状。
 */
@Serializable
data class EvidenceBundle(
    /** 本次使用的 nonce（服务端下发或本地兜底生成）。 */
    val nonce: String,
    /** nonce 来源："server"（已服务端化）/ "local"（兜底，防重放无效）。 */
    val nonceSource: String,
    /** Play Integrity 令牌原文；无 GMS / 未配项目号 / 请求失败时为 null。服务端解码。 */
    val playIntegrityToken: String? = null,
    /** Key Attestation 证书链（Base64 NO_WRAP DER，leaf→root）；服务端验链到 Google 硬件根 CA。 */
    val keyAttestationChainDerB64: List<String> = emptyList(),
    /** 本地 RiskReport（仅参考，不可信）。 */
    val localReport: RiskReport,
    val schemaVersion: Int = 1,
)
