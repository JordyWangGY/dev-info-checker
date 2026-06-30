package com.devcheck.server

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NonceServiceTest {

    @Test
    fun issuedNonceConsumesExactlyOnce() {
        val svc = NonceService()
        val n = svc.issue(now = 1000)
        assertTrue(svc.consume(n, now = 1000))   // 首次通过
        assertFalse(svc.consume(n, now = 1000))  // 重放被拒（单次）
    }

    @Test
    fun expiredNonceRejected() {
        val svc = NonceService(ttlMs = 60_000)
        val n = svc.issue(now = 0)
        assertFalse(svc.consume(n, now = 60_001)) // 超 TTL
    }

    @Test
    fun unknownNonceRejected() {
        assertFalse(NonceService().consume("never-issued"))
    }
}
