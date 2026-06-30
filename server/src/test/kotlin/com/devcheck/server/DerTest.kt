package com.devcheck.server

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * 验证 KeyAttestationVerifier 依赖的 DER 解析：从一个仿 KeyDescription 的 SEQUENCE 里
 * 取出第 2 个字段(attestationSecurityLevel ENUM) 与第 5 个字段(attestationChallenge OCTET STRING)。
 */
class DerTest {

    /** 小于 128 字节的定长 TLV 编码。 */
    private fun tlv(tag: Int, content: ByteArray): ByteArray =
        byteArrayOf(tag.toByte(), content.size.toByte()) + content

    @Test
    fun parsesKeyDescriptionFields() {
        val challenge = "NONCE-CHALLENGE".toByteArray()
        // KeyDescription ≈ SEQUENCE { INTEGER ver, ENUM secLevel, INTEGER kmVer, ENUM kmSec, OCTET challenge }
        val inner = tlv(0x02, byteArrayOf(3)) +          // [0] attestationVersion = 3
            tlv(0x0A, byteArrayOf(1)) +                  // [1] attestationSecurityLevel = TEE(1)
            tlv(0x02, byteArrayOf(4)) +                  // [2] keymasterVersion
            tlv(0x0A, byteArrayOf(1)) +                  // [3] keymasterSecurityLevel
            tlv(0x04, challenge)                         // [4] attestationChallenge
        val seqBytes = tlv(Der.SEQUENCE, inner)

        val seq = Der.parse(seqBytes, 0)
        assertEquals(Der.SEQUENCE, seq.tag)
        val fields = Der.children(seqBytes, seq)
        assertTrue(fields.size >= 5)
        assertEquals(1, Der.intValue(seqBytes, fields[1]))                 // securityLevel=TEE
        assertArrayEquals(challenge, Der.content(seqBytes, fields[4]))     // challenge 提取正确
    }
}
