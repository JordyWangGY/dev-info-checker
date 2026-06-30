package com.devcheck.server

/**
 * 极简 DER 解析：仅够从 Key Attestation 扩展(OID 1.3.6.1.4.1.11129.2.1.17)里取
 * KeyDescription 的字段（attestationSecurityLevel、attestationChallenge）。
 * 不做完整 ASN.1，只支持定长编码。
 */
object Der {
    const val SEQUENCE = 0x30
    const val OCTET_STRING = 0x04

    data class TLV(val tag: Int, val length: Int, val contentOffset: Int) {
        val end: Int get() = contentOffset + length
    }

    /** 解析 [data] 在 [offset] 处的一个 TLV（支持长度的长形式）。 */
    fun parse(data: ByteArray, offset: Int): TLV {
        var i = offset
        val tag = data[i].toInt() and 0xFF
        i++
        var len = data[i].toInt() and 0xFF
        i++
        if (len and 0x80 != 0) {
            val n = len and 0x7F
            len = 0
            repeat(n) { len = (len shl 8) or (data[i].toInt() and 0xFF); i++ }
        }
        return TLV(tag, len, i)
    }

    /** 某 SEQUENCE 的直接子 TLV 列表。 */
    fun children(data: ByteArray, seq: TLV): List<TLV> {
        val out = ArrayList<TLV>()
        var i = seq.contentOffset
        while (i < seq.end) {
            val t = parse(data, i)
            out += t
            i = t.end
        }
        return out
    }

    fun content(data: ByteArray, tlv: TLV): ByteArray =
        data.copyOfRange(tlv.contentOffset, tlv.end)

    fun intValue(data: ByteArray, tlv: TLV): Int {
        var v = 0
        for (j in tlv.contentOffset until tlv.end) v = (v shl 8) or (data[j].toInt() and 0xFF)
        return v
    }
}
