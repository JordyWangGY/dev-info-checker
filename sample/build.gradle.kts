plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.devcheck.sample"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "com.devcheck.sample"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "1.0"
    }

    signingConfigs {
        // 演示用 release 签名（随仓库提供的一次性 keystore，非生产密钥）。
        // 目的：让 install.sh 默认能打「非 debuggable」的 release 包并直接安装。
        create("release") {
            storeFile = file("keystore/devcheck-release.jks")
            storePassword = "devcheck"
            keyAlias = "devcheck"
            keyPassword = "devcheck"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":sdk"))
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.google.material)
}
