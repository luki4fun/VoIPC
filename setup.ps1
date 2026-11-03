# VoIPC Windows development environment setup
# Run as Administrator (elevated) for winget installs.
#
# Installs: Rust (MSVC), Node.js, CMake, NASM, LLVM, protoc; checks for Visual Studio Build Tools.
# FFmpeg comes with the first build (tools/tasks/desktop.mjs).
# Then runs npm ci in the client directory.

$ErrorActionPreference = "Stop"

function Test-Command($cmd) { $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue) }

Write-Host "`n=== VoIPC Windows Setup ===" -ForegroundColor Cyan

# --- Rust ---
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

# --- Node.js ---
if (Test-Command "node") {
    Write-Host "[ok] Node.js already installed ($(node --version))" -ForegroundColor Green
} else {
    Write-Host "[..] Installing Node.js via winget..." -ForegroundColor Yellow
    winget install --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
    Write-Host "[ok] Node.js installed (restart terminal to use)" -ForegroundColor Green
}

# --- CMake ---
if (Test-Command "cmake") {
    Write-Host "[ok] CMake already installed ($(cmake --version | Select-Object -First 1))" -ForegroundColor Green
} else {
    Write-Host "[..] Installing CMake via winget..." -ForegroundColor Yellow
    winget install --id Kitware.CMake --accept-source-agreements --accept-package-agreements
    Write-Host "[ok] CMake installed (restart terminal to use)" -ForegroundColor Green
}

# --- NASM ---
if (Test-Command "nasm") {
    Write-Host "[ok] NASM already installed ($(nasm -v 2>&1 | Select-Object -First 1))" -ForegroundColor Green
} else {
    Write-Host "[..] Installing NASM via winget..." -ForegroundColor Yellow
    winget install --id NASM.NASM --accept-source-agreements --accept-package-agreements
    Write-Host "[ok] NASM installed (restart terminal to use)" -ForegroundColor Green
}

# --- LLVM (needed by bindgen for FFmpeg Rust bindings) ---
$llvmPath = "C:\Program Files\LLVM\bin\libclang.dll"
if (Test-Path $llvmPath) {
    Write-Host "[ok] LLVM already installed" -ForegroundColor Green
} else {
    Write-Host "[..] Installing LLVM via winget..." -ForegroundColor Yellow
    winget install --id LLVM.LLVM --accept-source-agreements --accept-package-agreements
    Write-Host "[ok] LLVM installed" -ForegroundColor Green
}

# --- protoc (needed by the libsignal-protocol build script) ---
if (Test-Command "protoc") {
    Write-Host "[ok] protoc already installed" -ForegroundColor Green
} else {
    Write-Host "[..] Installing protoc via winget..." -ForegroundColor Yellow
    winget install --id Google.Protobuf --accept-source-agreements --accept-package-agreements
    Write-Host "[ok] protoc installed (restart terminal to use)" -ForegroundColor Green
}

# --- Visual Studio Build Tools ---
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

# --- FFmpeg ---
# Nothing to install: the first build downloads the pinned FFmpeg 8.x the
# releases use (SHA-256 checked), unless FFMPEG_DIR points at one already.

# --- npm ci ---
if (Test-Command "npm") {
    Write-Host "[..] Running npm ci in client/..." -ForegroundColor Yellow
    Push-Location "$PSScriptRoot\client"
    npm ci
    Pop-Location
    Write-Host "[ok] npm dependencies installed" -ForegroundColor Green
} else {
    Write-Host "[!!] npm not available yet - restart your terminal, then run: cd client; npm ci" -ForegroundColor Yellow
}

Write-Host "`n=== Setup complete ===" -ForegroundColor Cyan
Write-Host "If tools were newly installed, restart your terminal so PATH updates take effect."
Write-Host "Then run:  npm run dev    (debug)  or  npm run build  (release)"
Write-Host "           npm run --silent   lists every build task`n"
