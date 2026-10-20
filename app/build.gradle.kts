plugins {
    id("com.android.application")
}

android {
    namespace = "com.example.adshield"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.adshield"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
            // للاستخدام الشخصي: توقيع بمفتاح debug عشان تقدر تثبّت الـ APK مباشرة
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

// مفيش أي dependencies: التطبيق يعتمد على Android SDK فقط، فيطلع APK صغير وخفيف.
