package com.devcheck.server

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DecisionSignerTest {

    @Test
    fun signedJwtVerifiesAndTamperFails() {
        val signer = DecisionSigner()
        val jwt = signer.sign("""{"verdict":"GENUINE","score":0}""")
        assertTrue(signer.verify(jwt))

        // 篡改 payload 段 → 验签失败
        val parts = jwt.split(".")
        val tampered = parts[0] + "." + parts[1].dropLast(2) + "AA" + "." + parts[2]
        assertFalse(signer.verify(tampered))
    }

    @Test
    fun otherKeyCannotVerify() {
        val a = DecisionSigner()
        val b = DecisionSigner()
        val jwt = a.sign("""{"x":1}""")
        assertFalse(a.verify(jwt, key = b.publicKey)) // 换公钥验不过
    }
}
