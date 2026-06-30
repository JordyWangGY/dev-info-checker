@file:Suppress("UnstableApiUsage")

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "dev-info-checker"

// 阶段一：纯客户端
include(":protocol", ":sdk", ":sample")
// 阶段二：服务端权威裁决（纯 JVM，复用 :protocol；只用 JDK + kotlinx-serialization，无新依赖）
include(":server")
