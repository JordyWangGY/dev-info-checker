package com.devcheck.server

import com.devcheck.protocol.EvidenceBundle
import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.Json
import java.net.InetSocketAddress

/**
 * 演示服务端（JDK 内置 HttpServer，零额外依赖）：
 *   GET  /v1/nonce   → 下发一次性 nonce
 *   POST /v1/attest  → 收 EvidenceBundle(JSON)，跑验证流水线，回 Outcome(JSON, 含 Decision JWT)
 *
 * 仅供本机联调；生产路由层用 Ktor 等替换，验证逻辑（AttestService 等）不变。
 */
fun main() {
    val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    val nonces = NonceService()
    val svc = AttestService(nonces)
    val port = System.getenv("PORT")?.toIntOrNull() ?: 8080
    val server = HttpServer.create(InetSocketAddress(port), 0)

    server.createContext("/v1/nonce") { ex ->
        val body = """{"nonce":"${nonces.issue()}","source":"server"}""".toByteArray()
        ex.responseHeaders.add("Content-Type", "application/json")
        ex.sendResponseHeaders(200, body.size.toLong())
        ex.responseBody.use { it.write(body) }
    }

    server.createContext("/v1/attest") { ex ->
        val resp = runCatching {
            val bundle = json.decodeFromString(EvidenceBundle.serializer(), ex.requestBody.readBytes().decodeToString())
            json.encodeToString(AttestService.Outcome.serializer(), svc.handle(bundle))
        }.getOrElse { """{"accepted":false,"verdict":"UNKNOWN","score":0,"reasons":["bad request: ${it.message}"]}""" }
        val body = resp.toByteArray()
        ex.responseHeaders.add("Content-Type", "application/json")
        ex.sendResponseHeaders(200, body.size.toLong())
        ex.responseBody.use { it.write(body) }
    }

    server.start()
    println("DevCheck phase-2 server on :$port  (GET /v1/nonce, POST /v1/attest)")
}
