plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    application
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // 复用客户端/服务端共享的 DTO + 信号目录 + 评分权重，保证两端口径一致
    implementation(project(":protocol"))
    implementation(libs.kotlinx.serialization.json)

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    // 演示服务端：JDK 内置 HttpServer，零额外依赖。/v1/nonce 与 /v1/attest
    mainClass.set("com.devcheck.server.MainKt")
}

tasks.test {
    useJUnitPlatform()
}
