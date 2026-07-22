#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)]
    [string]$GigapipeUrl,           # e.g. http://xops-host:3100
    [string]$OtelVersion = "0.127.0",
    [switch]$IncludeSysmon,
    [switch]$IncludeHyperV
)

$ErrorActionPreference = "Stop"
$InstallDir = "C:\Program Files\panops-otelcol"
$ConfigFile = "$InstallDir\otelcol-config.yaml"

Write-Host "==> Downloading otelcol-contrib $OtelVersion..."
$msiUrl = "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v$OtelVersion/otelcol-contrib_${OtelVersion}_windows_amd64.msi"
$msiPath = "$env:TEMP\otelcol-contrib.msi"
Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath
Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /quiet INSTALLDIR=`"$InstallDir`"" -Wait

Write-Host "==> Writing config..."
$configContent = Get-Content -Path "$PSScriptRoot\otelcol-windows-config.yaml" -Raw
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$configContent | Out-File -FilePath $ConfigFile -Encoding utf8

# Set env vars for the service
[System.Environment]::SetEnvironmentVariable("GIGAPIPE_URL", $GigapipeUrl, "Machine")

if ($IncludeSysmon) {
    Write-Host "==> Downloading and installing Sysmon..."
    $sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
    $sysmonZip = "$env:TEMP\Sysmon.zip"
    Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip
    Expand-Archive -Path $sysmonZip -DestinationPath "$env:TEMP\sysmon" -Force
    # Use default Sysmon config (SwiftOnSecurity recommended)
    $sysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    Invoke-WebRequest -Uri $sysmonConfigUrl -OutFile "$env:TEMP\sysmon-config.xml"
    & "$env:TEMP\sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmon-config.xml"
}

Write-Host "==> Installing otelcol as Windows service..."
$svcArgs = "--config `"$ConfigFile`""
New-Service -Name "panops-otelcol" -BinaryPathName "`"$InstallDir\otelcol-contrib.exe`" $svcArgs" `
            -DisplayName "PanOps OpenTelemetry Collector" `
            -StartupType Automatic -Description "Ships Windows events and metrics to PanOps"
Start-Service -Name "panops-otelcol"

Write-Host ""
Write-Host "==> PanOps otelcol installed and running"
Write-Host "==> Events will appear in Gigapipe at: $GigapipeUrl"
Write-Host "==> Service: panops-otelcol (use Get-Service panops-otelcol to check status)"
