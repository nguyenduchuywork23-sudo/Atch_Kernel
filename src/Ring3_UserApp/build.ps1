$ErrorActionPreference = "Stop"
$WorkingDir = "C:\Users\Asus\Atch_Kernel\src\Ring3_UserApp"
Set-Location $WorkingDir

Write-Host "1. Installing WebView2 SDK via NuGet..."
if (!(Test-Path "nuget.exe")) {
    Invoke-WebRequest "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile "nuget.exe"
}
# -ExcludeVersion ensures the folder is exactly 'Microsoft.Web.WebView2'
.\nuget.exe install Microsoft.Web.WebView2 -Version 1.0.2592.51 -OutputDirectory "packages" -ExcludeVersion

Write-Host "2. Finding CMake from Visual Studio..."
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$cmakePath = & $vswhere -latest -find "**\cmake.exe" | Select-Object -First 1

if ([string]::IsNullOrWhiteSpace($cmakePath)) {
    Write-Host "CMake not found! Please install C++ Desktop Workload in Visual Studio." -ForegroundColor Red
    exit 1
}

Write-Host "Found CMake at: $cmakePath"

Write-Host "3. Generating Build Files..."
# Chạy CMake từ thư mục Ring3_UserApp, trỏ source vào host/
& $cmakePath -B build_host host "-DWEBVIEW2_DIR=$WorkingDir\packages\Microsoft.Web.WebView2\build\native"

Write-Host "4. Building C++ Host..."
& $cmakePath --build build_host --config Release

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build Succeeded!" -ForegroundColor Green
    Write-Host "Execute: $WorkingDir\build_host\Release\AtchKernelHost.exe"
} else {
    Write-Host "Build Failed!" -ForegroundColor Red
}
