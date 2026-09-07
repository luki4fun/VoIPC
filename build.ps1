# Release build (cargo tauri build)

# Sync version from workspace Cargo.toml → tauri.conf.json & package.json
$version = (Select-String -Path "$PSScriptRoot\Cargo.toml" -Pattern '^version\s*=\s*"(.*)"' | Select-Object -First 1).Matches.Groups[1].Value
foreach ($file in @("$PSScriptRoot\client\src-tauri\tauri.conf.json", "$PSScriptRoot\client\package.json")) {
    (Get-Content $file -Raw) -replace '"version":\s*"[^"]*"', "`"version`": `"$version`"" | Set-Content $file -NoNewline
}

# Honour a pre-set VCPKG_ROOT/LIBCLANG_PATH (CI images ship vcpkg at C:\vcpkg)
if (-not $env:VCPKG_ROOT)    { $env:VCPKG_ROOT    = "C:\Program Files\vcpkg" }
if (-not $env:LIBCLANG_PATH) { $env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin" }
$env:CMAKE_GENERATOR  = "Visual Studio 17 2022"
$env:FFMPEG_DIR       = "$env:VCPKG_ROOT\installed\x64-windows"
$env:PKG_CONFIG_PATH  = "$env:VCPKG_ROOT\installed\x64-windows\lib\pkgconfig"

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

# ── Stage vcpkg DLLs for Tauri bundling ──────────────────────────────────
# Tauri's bundle.resources includes these in the NSIS installer next to the exe.
$dllStaging = "$PSScriptRoot\client\src-tauri\external-dlls"
if (Test-Path $dllStaging) { Remove-Item $dllStaging -Recurse -Force }
New-Item -ItemType Directory -Path $dllStaging | Out-Null

# Copy FFmpeg, x265, and transitive dependency DLLs from vcpkg.
# vpl/libvpl: Intel oneVPL dispatcher pulled in by ffmpeg[qsv] (NVENC/AMF need
# no DLLs — they load from the GPU driver at runtime).
$dllPatterns = @("av*.dll", "sw*.dll", "x265*.dll", "libx265*.dll", "postproc*.dll", "turbojpeg.dll", "vpl*.dll", "libvpl*.dll")
foreach ($pattern in $dllPatterns) {
    Get-ChildItem "$vcpkgBin\$pattern" -ErrorAction SilentlyContinue |
        Copy-Item -Destination $dllStaging
}
$stagedCount = (Get-ChildItem "$dllStaging\*.dll" -ErrorAction SilentlyContinue).Count
Write-Host "[ok] Staged $stagedCount DLLs for bundling" -ForegroundColor Green

# Tell Tauri to bundle the staged DLLs, and disable the Linux-only AppImage hook
# (beforeBundleCommand stages Linux shared libraries and needs ldd + an ELF binary).
# An empty hook string is treated as "no hook" by the Tauri CLI.
#
# This must go through --config: the TAURI_CONFIG environment variable that
# Tauri v1 honoured is silently ignored by the v2 CLI, so setting it there left
# the FFmpeg DLLs out of the installer without any warning.
# bundle.active is unset in tauri.conf.json, which means off — without this a
# release build produces the bare .exe and silently skips the installer.
$tauriConfig = '{"build":{"beforeBundleCommand":""},"bundle":{"active":true,"resources":{"external-dlls/*":"./"}}}'

Set-Location -Path "$PSScriptRoot\client"
if (-not (Test-Path "node_modules")) { npm install }
npx tauri build --config $tauriConfig @args
