package com.devcheck.server

import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * 一次性 nonce（阶段二批次一 2.1）：下发带 TTL 的随机挑战值，**单次消费**防重放。
 * 内存实现（演示）；生产应换 Redis 等带 TTL 的共享存储。
 */
class NonceService(private val ttlMs: Long = 5 * 60 * 1000) {

    private class Entry(val expiresAt: Long, @Volatile var used: Boolean = false)

    private val store = ConcurrentHashMap<String, Entry>()
    private val rng = SecureRandom()
    private val enc = Base64.getUrlEncoder().withoutPadding()

    fun issue(now: Long = System.currentTimeMillis()): String {
        val nonce = enc.encodeToString(ByteArray(24).also { rng.nextBytes(it) })
        store[nonce] = Entry(now + ttlMs)
        return nonce
    }

    /** 存在、未过期、未用过才通过；通过即标记已用（单次）。 */
    fun consume(nonce: String, now: Long = System.currentTimeMillis()): Boolean {
        val e = store[nonce] ?: return false
        if (now > e.expiresAt) { store.remove(nonce); return false }
        synchronized(e) {
            if (e.used) return false
            e.used = true
        }
        return true
    }

    fun purgeExpired(now: Long = System.currentTimeMillis()) {
        store.entries.removeIf { now > it.value.expiresAt }
    }
}
