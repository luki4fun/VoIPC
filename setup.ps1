# VoIPC Windows development environment setup
# Run as Administrator (elevated) for winget installs.
#
# Installs: Rust (MSVC), Node.js, CMake, NASM, LLVM, Visual Studio Build Tools, vcpkg + FFmpeg.
# Then runs npm install in the client directory.

$ErrorActionPreference = "Stop"

function Test-Command($cmd) { $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue) }

Write-Host "`n=== VoIPC Windows Setup ===" -ForegroundColor Cyan

# ── Rust ──────────────────────────────────────────────────────────────────
if (Test-Command "rustc") {
    Write-Host "[ok] Rust already installed ($(rustc --version))" -ForegroundColor Green
} else {
    Write-Host "[..] Installing Rust via rustup..." -ForegroundColor Yellow
    $rustupInit = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInit
    & $rustupInit -y --default-toolchain stable-x86_64-pc-windows-msvc
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    Write-Host "[ok] Rust installed" -ForegroundColor Green
}

# ── Node.js ───────────────────────────────────────────────────────────────
if (Test-Command "node") {
    Write-Host "[ok] Node.js already installed ($(node --version))" -ForegroundColor Green
} else {
    Write-Host "[..] Installing Node.js via winget..." -ForegroundColor Yellow
    winget install --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
    Write-Host "[ok] Node.js installed (restart terminal to use)" -ForegroundColor Green
}

# ── CMake ─────────────────────────────────────────────────────────────────
if (Test-Command "cmake") {
    Write-Host "[ok] CMake already installed ($(cmake --version | Select-Object -First 1))" -ForegroundColor Green
} else {
    Write-Host "[..] Installing CMake via winget..." -ForegroundColor Yellow
    winget install --id Kitware.CMake --accept-source-agreements --accept-package-agreements
    Write-Host "[ok] CMake installed (restart terminal to use)" -ForegroundColor Green
}

# ── NASM ──────────────────────────────────────────────────────────────────
if (Test-Command "nasm") {
    Write-Host "[ok] NASM already installed ($(nasm -v 2>&1 | Select-Object -First 1))" -ForegroundColor Green
} else {
    Write-Host "[..] Installing NASM via winget..." -ForegroundColor Yellow
    winget install --id NASM.NASM --accept-source-agreements --accept-package-agreements
    Write-Host "[ok] NASM installed (restart terminal to use)" -ForegroundColor Green
}

# ── LLVM (needed by bindgen for FFmpeg Rust bindings) ────────────────────
$llvmPath = "C:\Program Files\LLVM\bin\libclang.dll"
if (Test-Path $llvmPath) {
    Write-Host "[ok] LLVM already installed" -ForegroundColor Green
} else {
    Write-Host "[..] Installing LLVM via winget..." -ForegroundColor Yellow
    winget install --id LLVM.LLVM --accept-source-agreements --accept-package-agreements
    Write-Host "[ok] LLVM installed" -ForegroundColor Green
}

# ── Visual Studio Build Tools ─────────────────────────────────────────────
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    $vsInstalls = & $vsWhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property displayName 2>$null
    if ($vsInstalls) {
        Write-Host "[ok] Visual Studio C++ tools found" -ForegroundColor Green
    } else {
        Write-Host "[!!] Visual Studio found but C++ workload missing" -ForegroundColor Red
        Write-Host "     Run Visual Studio Installer and add 'Desktop development with C++'" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!!] Visual Studio Build Tools not found" -ForegroundColor Red
    Write-Host "     Install from: https://visualstudio.microsoft.com/visual-cpp-build-tools/" -ForegroundColor Yellow
    Write-Host "     Select the 'Desktop development with C++' workload" -ForegroundColor Yellow
}

# ── vcpkg + FFmpeg ───────────────────────────────────────────────────────
$vcpkgRoot = "E:\Projekte\luki4funProd\vcpkg"
if (Test-Path "$vcpkgRoot\vcpkg.exe") {
    Write-Host "[ok] vcpkg already installed at $vcpkgRoot" -ForegroundColor Green
} else {
    Write-Host "[..] Cloning vcpkg..." -ForegroundColor Yellow
    git clone https://github.com/Microsoft/vcpkg.git $vcpkgRoot
    & "$vcpkgRoot\bootstrap-vcpkg.bat"
    Write-Host "[ok] vcpkg installed" -ForegroundColor Green
}
$ffmpegHeader = "$vcpkgRoot\installed\x64-windows\include\libavcodec\avcodec.h"
$ffmpegLib = "$vcpkgRoot\installed\x64-windows\lib\avcodec.lib"
$x265Lib = "$vcpkgRoot\installed\x64-windows\lib\x265.lib"
if ((Test-Path $ffmpegHeader) -and (Test-Path $ffmpegLib) -and (Test-Path $x265Lib)) {
    Write-Host "[ok] FFmpeg + x265 already installed via vcpkg" -ForegroundColor Green
} else {
    if ((Test-Path $ffmpegLib) -and -not (Test-Path $x265Lib)) {
        Write-Host "[!!] FFmpeg installed but WITHOUT x265 — reinstalling with x265..." -ForegroundColor Yellow
        & "$vcpkgRoot\vcpkg.exe" remove ffmpeg:x64-windows
    } elseif (Test-Path $ffmpegLib) {
        Write-Host "[!!] FFmpeg libs found but headers missing - reinstalling..." -ForegroundColor Yellow
        & "$vcpkgRoot\vcpkg.exe" remove ffmpeg:x64-windows
    }
    Write-Host "[..] Installing FFmpeg with x265 via vcpkg (this may take 15-30 minutes)..." -ForegroundColor Yellow
    & "$vcpkgRoot\vcpkg.exe" install "ffmpeg[x265]:x64-windows" --recurse
    if (-not (Test-Path $ffmpegHeader)) {
        Write-Host "[!!] FFmpeg headers still missing after install!" -ForegroundColor Red
        Write-Host "     Expected: $ffmpegHeader" -ForegroundColor Yellow
        Write-Host "     Try: vcpkg remove ffmpeg:x64-windows; vcpkg install ffmpeg[x265]:x64-windows" -ForegroundColor Yellow
    } elseif (-not (Test-Path $x265Lib)) {
        Write-Host "[!!] x265 still missing after install!" -ForegroundColor Red
        Write-Host "     Try: vcpkg remove ffmpeg:x64-windows; vcpkg install `"ffmpeg[x265]:x64-windows`"" -ForegroundColor Yellow
    } else {
        Write-Host "[ok] FFmpeg + x265 installed" -ForegroundColor Green
    }
}

# ── npm install ───────────────────────────────────────────────────────────
if (Test-Command "npm") {
    Write-Host "[..] Running npm install in client/..." -ForegroundColor Yellow
    Push-Location "$PSScriptRoot\client"
    npm install
    Pop-Location
    Write-Host "[ok] npm dependencies installed" -ForegroundColor Green
} else {
    Write-Host "[!!] npm not available yet - restart your terminal, then run: cd client; npm install" -ForegroundColor Yellow
}

Write-Host "`n=== Setup complete ===" -ForegroundColor Cyan
Write-Host "If tools were newly installed, restart your terminal so PATH updates take effect."
Write-Host "Then run:  .\dev.ps1    (debug)  or  .\build.ps1  (release)`n"
