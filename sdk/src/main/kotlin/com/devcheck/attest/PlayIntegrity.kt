package com.devcheck.attest

import android.content.Context
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityServiceException
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Play Integrity（有 GMS 时的最强硬件背书）。
 *
 * 阶段一只**采集**令牌——令牌是加密的，必须在**阶段二服务端**用 Play Integrity API 解码，
 * 才能读到 deviceIntegrity（含 MEETS_VIRTUAL_INTEGRITY=模拟器）等结论。客户端不解码、不裁决。
 *
 * 但请求**失败时**的 [IntegrityErrorCode]（[errorCode]）无需解码即暴露本机 GMS/Play 环境，
 * 由 AttestDetector 映射为 `attest.play_integrity.env` 计分信号。
 */
internal object PlayIntegrity {

    /** errorCode：成功或非 IntegrityServiceException 时为 [NO_CODE]。 */
    const val NO_CODE = Int.MIN_VALUE

    data class Result(
        val available: Boolean,
        val token: String?,
        val error: String?,
        val errorCode: Int = NO_CODE,
    )

    suspend fun request(ctx: Context, cloudProjectNumber: Long, nonce: String): Result = try {
        val manager = IntegrityManagerFactory.create(ctx.applicationContext)
        val resp = manager.requestIntegrityToken(
            IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .setCloudProjectNumber(cloudProjectNumber)
                .build(),
        ).await()
        Result(true, resp.token(), null)
    } catch (t: Throwable) {
        val code = (t as? IntegrityServiceException)?.errorCode ?: NO_CODE
        Result(false, null, "${t.javaClass.simpleName}:${t.message ?: ""}", code)
    }
}

private suspend fun <T> Task<T>.await(): T = suspendCancellableCoroutine { cont ->
    addOnSuccessListener { cont.resume(it) }
    addOnFailureListener { cont.resumeWithException(it) }
    addOnCanceledListener { cont.cancel() }
}
