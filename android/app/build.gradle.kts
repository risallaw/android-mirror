plugins {
    alias(libs.plugins.android.application)
}

// Builds the Rust core (android/core) into build/rustJniLibs/<abi>/libmirror_core.so.
val repoRoot = rootProject.layout.projectDirectory.dir("..")
val rustJniLibs = layout.buildDirectory.dir("rustJniLibs")

android {
    namespace = "dev.local.androidmirror"
    compileSdk = 36
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "dev.local.androidmirror"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        release {
            // Not minified: no R8 keep rules exist for the JNI surface (NativeCore's natives and the
            // CoreCallbacks methods android/core looks up by name). Add them before enabling this.
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            jniLibs.directories.add(rustJniLibs.get().asFile.path)
        }
    }
}

// AGP 9 exposes the NDK location lazily via androidComponents (android.ndkDirectory is gone);
// resolving it in doFirst keeps the task configuration-cache friendly.
val cargoNdkBuild = tasks.register<Exec>("cargoNdkBuild") {
    group = "build"
    description = "Build mirror-android-core with cargo-ndk"
    val ndkDir: Provider<Directory> = androidComponents.sdkComponents.ndkDirectory
    val outDir = rustJniLibs
    workingDir = repoRoot.asFile
    outputs.dir(outDir)
    // Cargo's own incremental build is the up-to-date check, so the task always runs.
    outputs.upToDateWhen { false }
    doFirst {
        // Either variable, even empty, replaces the target's rustflags in .cargo/config.toml (the
        // 16 KB page-size link flag and NEON), giving a library that fails on 16 KB-page devices.
        val overriding = listOf("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS").filter { it in (this as Exec).environment }
        if (overriding.isNotEmpty()) {
            throw GradleException(
                "cargoNdkBuild: unset ${overriding.joinToString(" and ")}: it would replace the Android " +
                    "rustflags in .cargo/config.toml (16 KB page alignment, NEON). Add flags there instead.",
            )
        }
        // Drop libs of ABIs that are no longer built so they cannot leak into the APK.
        outDir.get().asFile.deleteRecursively()
        (this as Exec).environment("ANDROID_NDK_HOME", ndkDir.get().asFile.absolutePath)
    }
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "--platform", "29",
        "-o", outDir.get().asFile.absolutePath,
        "build", "--release", "-p", "mirror-android-core",
    )
}

tasks.named("preBuild") {
    dependsOn(cargoNdkBuild)
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    testImplementation(libs.junit)
    // The real org.json (android.jar's is a stub in JVM tests) and the ICU rules Android uses.
    testImplementation(libs.json)
    testImplementation(libs.icu4j)
    androidTestImplementation(libs.androidx.test.runner)
}
