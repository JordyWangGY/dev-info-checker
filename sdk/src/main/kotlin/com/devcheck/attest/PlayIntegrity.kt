package com.devcheck.attest

import android.content.Context
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Play Integrity（有 GMS 时的最强硬件背书）。
 *
 * 阶段一只**采集**令牌——令牌是加密的，必须在**阶段二服务端**用 Play Integrity API 解码，
 * 才能读到 deviceIntegrity（含 MEETS_VIRTUAL_INTEGRITY=模拟器）等结论。客户端不解码、不裁决。
 */
internal object PlayIntegrity {

    data class Result(val available: Boolean, val token: String?, val error: String?)

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
        Result(false, null, "${t.javaClass.simpleName}:${t.message ?: ""}")
    }
}

private suspend fun <T> Task<T>.await(): T = suspendCancellableCoroutine { cont ->
    addOnSuccessListener { cont.resume(it) }
    addOnFailureListener { cont.resumeWithException(it) }
    addOnCanceledListener { cont.cancel() }
}
