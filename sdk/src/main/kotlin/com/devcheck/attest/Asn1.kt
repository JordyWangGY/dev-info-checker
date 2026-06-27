package com.devcheck.attest

/**
 * 极简 DER / ASN.1 解析器，仅覆盖解析 Key Attestation 扩展（KeyDescription）所需的结构。
 * 不引入第三方库（如 BouncyCastle），保持 SDK 轻量。
 */
internal object Asn1 {
    const val TAG_BOOLEAN = 0x01
    const val TAG_INTEGER = 0x02
    const val TAG_OCTET_STRING = 0x04
    const val TAG_ENUMERATED = 0x0A
    const val TAG_SEQUENCE = 0x30

    /** context [704] constructed（EXPLICIT），即 AuthorizationList 里的 rootOfTrust：字节 BF 85 40。 */
    const val TAG_ROOT_OF_TRUST = 0xBF8540

    data class Tlv(val tag: Int, val contentOffset: Int, val length: Int) {
        val end: Int get() = contentOffset + length
    }

    /** 解析 off 处的一个 TLV（支持高位 tag 与长格式 length）。 */
    fun parse(b: ByteArray, off: Int): Tlv {
        var p = off
        val first = b[p].toInt() and 0xFF
        p++
        var tag = first
        if (first and 0x1F == 0x1F) { // 高位 tag（多字节）
            var t = (first.toLong() and 0xFF)
            while (true) {
                val x = b[p].toInt() and 0xFF
                t = (t shl 8) or x.toLong()
                p++
                if (x and 0x80 == 0) break
            }
            tag = t.toInt()
        }
        var length = b[p].toInt() and 0xFF
        p++
        if (length and 0x80 != 0) { // 长格式
            val n = length and 0x7F
            length = 0
            for (i in 0 until n) {
                length = (length shl 8) or (b[p].toInt() and 0xFF)
                p++
            }
        }
        return Tlv(tag, p, length)
    }

    /** 解析某构造型 TLV 的所有直接子节点。 */
    fun children(b: ByteArray, parent: Tlv): List<Tlv> {
        val out = ArrayList<Tlv>()
        var p = parent.contentOffset
        while (p < parent.end) {
            val t = parse(b, p)
            out.add(t)
            p = t.end
        }
        return out
    }

    fun intValue(b: ByteArray, t: Tlv): Int {
        var v = 0
        for (i in 0 until t.length) v = (v shl 8) or (b[t.contentOffset + i].toInt() and 0xFF)
        return v
    }

    fun boolValue(b: ByteArray, t: Tlv): Boolean {
        for (i in 0 until t.length) if (b[t.contentOffset + i].toInt() != 0) return true
        return false
    }
}
