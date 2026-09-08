fn main() {
    // Android: the C++ parts (oboe-sys) leave libc++ symbols undefined —
    // operator new/delete, the guard functions, __cxa_pure_virtual. The NDK's
    // libc++_shared.so is packaged with the APK (tools/tasks/android.mjs stages
    // it into jniLibs), but Android's loader only resolves what a library's
    // DT_NEEDED lists. Without this link the app dies the moment it starts:
    // "dlopen failed: cannot locate symbol __cxa_pure_virtual".
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-lib=dylib=c++_shared");
    }
    tauri_build::build();
}
