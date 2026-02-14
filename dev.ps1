# Debug build + run (cargo tauri dev)
$env:VCPKG_ROOT       = "C:\Program Files\vcpkg"
$env:CMAKE_GENERATOR  = "Visual Studio 17 2022"
$env:FFMPEG_DIR       = "$env:VCPKG_ROOT\installed\x64-windows"
$env:PKG_CONFIG_PATH  = "$env:VCPKG_ROOT\installed\x64-windows\lib\pkgconfig"
$env:LIBCLANG_PATH    = "C:\Program Files\LLVM\bin"

# ── Detect MSVC and Windows SDK paths via vswhere ────────────────────────
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath  = $null
$msvcVer = $null
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vsPath) {
        $msvcVer = (Get-Content "$vsPath\VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt" -ErrorAction SilentlyContinue)
        if ($msvcVer) { $msvcVer = $msvcVer.Trim() }
    }
}
$sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
$sdkVer  = $null
if (Test-Path "$sdkRoot\Include") {
    $sdkVer = (Get-ChildItem "$sdkRoot\Include" -Directory | Sort-Object Name -Descending | Select-Object -First 1).Name
}

# Force MSVC compiler so cmake-based crates (aws-lc-sys etc.) don't pick up clang from PATH
if ($msvcVer) {
    $clExe = "$vsPath\VC\Tools\MSVC\$msvcVer\bin\Hostx64\x64\cl.exe"
    $env:CC  = $clExe
    $env:CXX = $clExe
}

# Build INCLUDE: MSVC + Windows SDK + vcpkg  (replicates what vcvarsall.bat sets up)
$vcpkgInclude = "$env:VCPKG_ROOT\installed\x64-windows\include"
$vcpkgLib     = "$env:VCPKG_ROOT\installed\x64-windows\lib"
$includePaths = @($vcpkgInclude)
$libPaths     = @($vcpkgLib)
if ($msvcVer) {
    $includePaths += "$vsPath\VC\Tools\MSVC\$msvcVer\include"
    $libPaths     += "$vsPath\VC\Tools\MSVC\$msvcVer\lib\x64"
}
if ($sdkVer) {
    $includePaths += "$sdkRoot\Include\$sdkVer\ucrt"
    $includePaths += "$sdkRoot\Include\$sdkVer\shared"
    $includePaths += "$sdkRoot\Include\$sdkVer\um"
    $libPaths     += "$sdkRoot\Lib\$sdkVer\ucrt\x64"
    $libPaths     += "$sdkRoot\Lib\$sdkVer\um\x64"
}
$env:INCLUDE = ($includePaths -join ";") + ";$env:INCLUDE"
$env:LIB     = ($libPaths -join ";") + ";$env:LIB"

# Bindgen (clang) needs explicit -I flags for MSVC/SDK headers (stdint.h etc.)
# Paths must be quoted because they contain spaces (e.g. "Program Files (x86)")
$clangArgs = @("`"-I$vcpkgInclude`"")
if ($msvcVer) {
    $clangArgs += "`"-I$vsPath\VC\Tools\MSVC\$msvcVer\include`""
}
if ($sdkVer) {
    $clangArgs += "`"-I$sdkRoot\Include\$sdkVer\ucrt`""
}
$env:BINDGEN_EXTRA_CLANG_ARGS = $clangArgs -join " "

# Put vcpkg DLLs (FFmpeg, turbojpeg, etc.) on PATH so the app finds them at runtime
$vcpkgBin = "$env:VCPKG_ROOT\installed\x64-windows\bin"
if ($env:PATH -notlike "*$vcpkgBin*") {
    $env:PATH = "$vcpkgBin;$env:PATH"
}

Set-Location -Path "$PSScriptRoot\client"
if (-not (Test-Path "node_modules")) { npm install }
npx tauri dev @args
