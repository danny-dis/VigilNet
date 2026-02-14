# Build script for VigilNet Android
# Requires: cargo-ndk, Android NDK

$ErrorActionPreference = "Stop"

Write-Host "Building VigilNet for Android targets..."

# Create jniLibs directory if it doesn't exist
$jniLibs = "android\app\src\main\jniLibs"
if (!(Test-Path $jniLibs)) {
    New-Item -ItemType Directory -Force -Path $jniLibs | Out-Null
}

# Define targets
$targets = @(
    "aarch64-linux-android",
    "armv7-linux-androideabi",
    "x86_64-linux-android",
    "i686-linux-android"
)

# Build for each target
foreach ($target in $targets) {
    Write-Host "Building for $target..."
    cargo ndk -t $target -o $jniLibs build --release
}

Write-Host "Build complete! Shared libraries placed in $jniLibs"
