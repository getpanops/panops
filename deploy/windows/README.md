# Windows OpenTelemetry Collector Agent

Ships Windows event logs and performance metrics to PanOps (Gigapipe).

## Prerequisites

- Windows Server 2019+ or Windows 10+ (for Sysmon support)
- PowerShell 5.1+
- Administrator privileges
- Network access to PanOps Gigapipe endpoint (default: http://panops-host:3100)

## Quick Start

### Basic Installation

```powershell
.\install.ps1 -GigapipeUrl "http://panops-host:3100"
```

### With Sysmon (Recommended)

```powershell
.\install.ps1 -GigapipeUrl "http://panops-host:3100" -IncludeSysmon
```

### With Hyper-V Events (Hyper-V Hosts Only)

```powershell
.\install.ps1 -GigapipeUrl "http://panops-host:3100" -IncludeHyperV
```

### With Both Sysmon and Hyper-V

```powershell
.\install.ps1 -GigapipeUrl "http://panops-host:3100" -IncludeSysmon -IncludeHyperV
```

## What Gets Collected

### Event Logs

- **Security**: Failed logins, policy changes, audit events
- **System**: Hardware errors, service failures
- **Application**: App-level events and errors
- **Sysmon** (if enabled): Process creation, network connections, file writes
- **Hyper-V** (if Hyper-V role installed): Virtualization events

### Performance Metrics

- CPU utilization
- Memory available and in-use
- Disk free space and I/O
- Network bytes sent/received

All data is enriched with `host.name` and `os.type: windows` attributes.

## Verification

### Check Service Status

```powershell
Get-Service panops-otelcol
```

Expected output: `Running`

### Generate Test Events

```powershell
net use \\localhost\IPC$ /user:nobody wrongpassword
```

Events should appear in Grafana Loki within 60 seconds.

### Check Metrics

Log into Grafana and query the Prometheus data source for `system.cpu.utilization`, `system.memory.available`, etc.

## Configuration

The otelcol config is installed to:

```
C:\Program Files\panops-otelcol\otelcol-config.yaml
```

### Changing the Gigapipe Endpoint

The `GIGAPIPE_URL` environment variable is set at the machine level during installation. To update it:

```powershell
[System.Environment]::SetEnvironmentVariable("GIGAPIPE_URL", "http://new-endpoint:3100", "Machine")
Restart-Service panops-otelcol
```

### Disabling Sysmon Events

Edit `otelcol-config.yaml` and remove or comment out the `windowseventlog/sysmon` receiver in the logs pipeline.

### Disabling Hyper-V Events

If Hyper-V events cause errors on non-Hyper-V hosts, edit `otelcol-config.yaml` and remove the `windowseventlog/hyperv` receiver.

## Airgap (Offline) Installation

For networks without internet access:

1. Download otelcol MSI on a machine with internet:
   ```powershell
   $Version = "0.127.0"
   $msiUrl = "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v$Version/otelcol-contrib_${Version}_windows_amd64.msi"
   Invoke-WebRequest -Uri $msiUrl -OutFile otelcol-contrib.msi
   ```

2. If using `-IncludeSysmon`, also download:
   ```powershell
   Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile sysmonconfig-export.xml
   ```

3. Modify `install.ps1` to reference local paths instead of URLs, then run on the target host.

## Updating otelcol

To update to a newer version:

1. Stop the service:
   ```powershell
   Stop-Service panops-otelcol
   ```

2. Download and install the new MSI (same URL with updated version number)

3. Update config if needed (copy new `otelcol-windows-config.yaml` to `C:\Program Files\panops-otelcol\otelcol-config.yaml`)

4. Restart the service:
   ```powershell
   Start-Service panops-otelcol
   ```

## Troubleshooting

### Service fails to start

Check the Windows Event Viewer under Application logs for otelcol errors. Common issues:

- `GIGAPIPE_URL` not set: Verify with `[System.Environment]::GetEnvironmentVariable("GIGAPIPE_URL", "Machine")`
- Config file syntax error: Run `otelcol-contrib.exe --config "C:\Program Files\panops-otelcol\otelcol-config.yaml" validate`
- Port already in use (rare): Check if another process is using ports 4317/4318

### Events not appearing in Loki

- Verify Gigapipe endpoint is reachable: `Test-NetConnection panops-host -Port 3100`
- Check for firewall rules blocking the connection
- Ensure at least one Security event exists (failed login test above)

### Memory usage too high

The batch processor defaults to 1000 events. To reduce memory, edit the config and lower `send_batch_size`.

## Manual Uninstall

```powershell
Stop-Service panops-otelcol
Remove-Service panops-otelcol
Remove-Item -Recurse -Force "C:\Program Files\panops-otelcol"
[System.Environment]::SetEnvironmentVariable("GIGAPIPE_URL", $null, "Machine")
```

If Sysmon was installed:

```powershell
& "C:\Program Files\Sysmon\Sysmon64.exe" -u
```
