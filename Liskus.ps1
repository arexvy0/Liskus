<# ============================================================================
  LiskusScanner (PowerShell)
  Author: arexvy
============================================================================ #>

[CmdletBinding()]
param(
  [string]$WebhookUrl = "",
  [string]$OutputDir = ".\scan_report",
  [string]$StringsExePath = ".\strings.exe",
  [int]$LateStartThresholdMin = 5,
  [switch]$ZipAndUpload # If set, a ZIP containing HTML+CSS will be uploaded to Discord as well.
)

# --------------------------- Helpers ---------------------------

function Write-Info($msg)  { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK($msg)    { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "[-] $msg" -ForegroundColor Red }

function Get-BootTime {
  try   { return (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
  catch { return (Get-Date).AddHours(-1) }
}

function Get-InstallDate {
  try   { return (Get-CimInstance Win32_OperatingSystem).InstallDate }
  catch { return $null }
}

function Get-LogonTime {
  try {
    $expl = Get-Process -Name explorer -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1
    if ($expl) { return $expl.StartTime }
  } catch {}
  # Fallback: boot time
  return Get-BootTime
}

function To-Relative($dt) {
  if (-not $dt) { return "n/a" }
  $ts = (Get-Date) - $dt
  $parts = @()
  if ($ts.Days)    { $parts += "$($ts.Days)d" }
  if ($ts.Hours)   { $parts += "$($ts.Hours)h" }
  if ($ts.Minutes) { $parts += "$($ts.Minutes)m" }
  if (-not $parts) { $parts = @("$([int][Math]::Max(0,[Math]::Round($ts.TotalSeconds)))s") }
  return ($parts -join " ")
}

function Normalize-Path([string]$p) {
  if ([string]::IsNullOrWhiteSpace($p)) { return $null }
  try {
    $p = $p.Trim('"').Trim()
    # Normalize slashes and case
    $p = $p -replace '/', '\'
    return $p
  } catch { return $p }
}

function Has-ValidSignature([string]$path) {
  try {
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
    return ($sig.Status -eq 'Valid')
  } catch {
    return $false
  }
}

function Get-NtfsVolumes {
  try {
    return (Get-Volume | Where-Object { $_.FileSystem -eq "NTFS" -and $_.DriveLetter })
  } catch {
    return @()
  }
}

# ---------------- General Info: Services & Processes ----------------

# Target set from your specification (services + processes)
$TargetEntries = @(
  @{ Label="PcaSvc";      Kind="Service"; Names=@("PcaSvc") },
  @{ Label="CDPUserSvc";  Kind="Service"; Names=@("CDPUserSvc","CDPUserSvc_*") },
  @{ Label="DPS";         Kind="Service"; Names=@("DPS") },
  @{ Label="SysMain";     Kind="Service"; Names=@("SysMain") },
  @{ Label="SgrmBroker";  Kind="Process"; Names=@("SgrmBroker") },
  @{ Label="EventLog";    Kind="Service"; Names=@("EventLog") },
  @{ Label="AppInfo";     Kind="Service"; Names=@("Appinfo") },
  @{ Label="WSearch";     Kind="Service"; Names=@("WSearch") },
  @{ Label="DusmSvc";     Kind="Service"; Names=@("DusmSvc") },
  @{ Label="WinDefend";   Kind="Service"; Names=@("WinDefend") },
  @{ Label="mpssvc";      Kind="Service"; Names=@("mpssvc") },
  @{ Label="Dnscache";    Kind="Service"; Names=@("Dnscache") },
  @{ Label="Schedule";    Kind="Service"; Names=@("Schedule") },
  @{ Label="PlugPlay";    Kind="Service"; Names=@("PlugPlay") },
  @{ Label="DiagTrack";   Kind="Service"; Names=@("DiagTrack") },
  @{ Label="BFE";         Kind="Service"; Names=@("BFE") },
  @{ Label="explorer";    Kind="Process"; Names=@("explorer") },
  @{ Label="csrss";       Kind="Process"; Names=@("csrss") },
  @{ Label="lsass";       Kind="Process"; Names=@("lsass") }
)

$BootTime = Get-BootTime

function Get-ProcService-State {
  param(
    [Parameter(Mandatory)][hashtable]$Entry
  )
  $label   = $Entry.Label
  $kind    = $Entry.Kind
  $names   = $Entry.Names

  $result = [ordered]@{
    label       = $label
    kind        = $kind
    status      = "unknown"
    disabled    = $false
    running     = $false
    startTime   = $null
    startRel    = "n/a"
    color       = "ok"    # ok | red | yellow
    detail      = ""
  }

  try {
    if ($kind -eq "Service") {
      # Many services may exist with wildcards (e.g., CDPUserSvc_4f5da)
      $svcs = @()
      foreach ($n in $names) {
        $svcs += Get-Service -Name $n -ErrorAction SilentlyContinue
      }
      if (-not $svcs) {
        $result.status = "not found"
        $result.color  = "red"
        return $result
      }

      # Prefer the one that's Running
      $svc = $svcs | Where-Object Status -eq 'Running' | Select-Object -First 1
      if (-not $svc) { $svc = $svcs | Select-Object -First 1 }

      $result.status   = $svc.Status.ToString()
      $result.running  = ($svc.Status -eq 'Running')
      # Disabled?
      try {
        $wmi = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction Stop
        $result.disabled = -not $wmi.StartMode -or ($wmi.StartMode -eq 'Disabled')
        $pid = $wmi.ProcessId
      } catch { $pid = $null }

      if ($pid) {
        try {
          $p = Get-Process -Id $pid -ErrorAction Stop
          $result.startTime = $p.StartTime
          $result.startRel  = To-Relative($p.StartTime)
        } catch {}
      }

      # Coloring rules
      if ($label -eq "DiagTrack" -and (-not $result.running -or $result.disabled)) {
        $result.color = "yellow"
      } elseif (-not $result.running -or $result.disabled) {
        $result.color = "red"
      } elseif ($result.startTime -and $result.startTime -gt $BootTime.AddMinutes($LateStartThresholdMin)) {
        $result.color = "red"
        $result.detail = "Late start (> $LateStartThresholdMin min after boot)"
      }

    } else {
      # Process
      $proc = $null
      foreach ($n in $names) {
        $p = Get-Process -Name $n -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1
        if ($p) { $proc = $p; break }
      }
      if (-not $proc) {
        $result.status = "not running"
        $result.color  = "red"
        return $result
      }
      $result.running   = $true
      $result.status    = "running"
      $result.startTime = $proc.StartTime
      $result.startRel  = To-Relative($proc.StartTime)
      if ($result.startTime -gt $BootTime.AddMinutes($LateStartThresholdMin)) {
        $result.color = "red"
        $result.detail = "Late start (> $LateStartThresholdMin min after boot)"
      }
    }
  } catch {
    $result.status = "error"
    $result.color  = "red"
    $result.detail = $_.Exception.Message
  }

  return [pscustomobject]$result
}

$ProcStates = foreach ($e in $TargetEntries) { Get-ProcService-State -Entry $e }

$GeneralInfo = [ordered]@{
  installDate = (Get-InstallDate)
  logonTime   = (Get-LogonTime)
  bootTime    = $BootTime
  processes   = $ProcStates
}

$WarnProcessCount = ($ProcStates | Where-Object { $_.color -ne 'ok' } | Measure-Object).Count

# ---------------- WinDefend (Event Log) ----------------

function Get-WinDefendFindings {
  $findings = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
  $items = @()

  try {
    $evts = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -ErrorAction Stop
    foreach ($e in $evts) {
      # Exclude "ScanType Antimalware" entries
      if ($e.Message -match '(?i)Scan\s*Type\s*:?\s*Antimalware') { continue }

      # Focus on detection-type events (1116/1117/1118), but accept others containing paths
      if ($e.Id -in 1116,1117,1118 -or $e.Message -match '(?i)[A-Z]:\\') {
        # Extract first path-like token
        $path = $null

        # Try quoted path first
        $m = [regex]::Match($e.Message, '(?i)"([A-Z]:\\[^"]+)"')
        if ($m.Success) { $path = $m.Groups[1].Value }
        if (-not $path) {
          $m = [regex]::Match($e.Message, '(?i)\b([A-Z]:\\[^\s"<>|]+)')
          if ($m.Success) { $path = $m.Groups[1].Value }
        }

        if ($path) {
          $n = Normalize-Path $path
          if ($findings.Add($n)) {
            $items += [pscustomobject]@{
              path = $n
              time = $e.TimeCreated
              eventId = $e.Id
            }
          }
        }
      }
    }
  } catch {
    Write-Warn "Failed to read Windows Defender events: $($_.Exception.Message)"
  }
  return ,$items
}

$WinDefendFindings = Get-WinDefendFindings
$WinDefendPathsSet = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
$null = $WinDefendFindings | ForEach-Object { $WinDefendPathsSet.Add($_.path) | Out-Null }

# ---------------- Executed Since Boot ----------------

function Get-ExecutedSinceBoot {
  $out = @{}
  $start = $BootTime

  # Prefer Sysmon (ID 1)
  $sysmon = $null
  try { $sysmon = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop } catch {}

  if ($sysmon -and $sysmon.IsEnabled) {
    Write-Info "Using Sysmon (Event ID 1) for executed processes"
    try {
      $flt = @{ LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 1; StartTime = $start }
      Get-WinEvent -FilterHashtable $flt -ErrorAction Stop | ForEach-Object {
        $msg = $_.Message
        $m = [regex]::Match($msg, '(?im)Image:\s*(.+)')
        if ($m.Success) {
          $p = Normalize-Path $m.Groups[1].Value.Trim()
          if ($p -and -not $out.ContainsKey($p)) { $out[$p] = $_.TimeCreated }
        }
      }
    } catch { Write-Warn "Sysmon read failed: $($_.Exception.Message)" }
  } else {
    # Fall back to Security 4688 (New Process Created)
    Write-Info "Using Security (4688) for executed processes"
    try {
      $flt = @{ LogName = "Security"; Id = 4688; StartTime = $start }
      Get-WinEvent -FilterHashtable $flt -ErrorAction Stop | ForEach-Object {
        $msg = $_.Message
        # Try English first, then a generic German-ish alternative
        $m = [regex]::Match($msg, '(?im)New Process Name:\s*(.+)')
        if (-not $m.Success) { $m = [regex]::Match($msg, '(?im)Neuer Prozessname:\s*(.+)') }
        if (-not $m.Success) { $m = [regex]::Match($msg, '(?im)Prozessname.*?:\s*(.+)') }
        if ($m.Success) {
          $p = Normalize-Path $m.Groups[1].Value.Trim()
          if ($p -and -not $out.ContainsKey($p)) { $out[$p] = $_.TimeCreated }
        }
      }
    } catch { Write-Warn "Security(4688) read failed: $($_.Exception.Message)" }
  }
  return $out
}

$ExecutedMap = Get-ExecutedSinceBoot

# ---------------- Deletions since Boot (USN or Sysmon Fallback) ----------------

function Get-DeletedEntries {
  $deleted = @()

  # Try PowerForensics first
  $pfLoaded = $false
  try {
    Import-Module PowerForensics -ErrorAction Stop
    $pfLoaded = $true
    Write-Info "Using PowerForensics USN records for deletions"
  } catch {
    Write-Warn "PowerForensics not available, falling back to Sysmon FileDelete (ID 23) if present."
  }

  if ($pfLoaded) {
    $vols = Get-NtfsVolumes
    foreach ($v in $vols) {
      $drive = $v.DriveLetter
      if (-not $drive) { continue }
      try {
        # Many versions expose Get-ForensicUSNRecord (capitalization can vary)
        $cmd = Get-Command -Name Get-ForensicUSNRecord -ErrorAction SilentlyContinue
        if (-not $cmd) { $cmd = Get-Command -Name Get-ForensicUsnRecord -ErrorAction SilentlyContinue }
        if ($cmd) {
          # Read records since boot
          $recs = & $cmd -Volume "$drive`:" -ErrorAction SilentlyContinue
          foreach ($r in $recs) {
            # Reason flags include Delete (0x00000010) or File delete close (0x00000100/0x00000200)
            $reason = 0
            try { $reason = [int]$r.Reason } catch {}
            if ( ($reason -band 0x10) -or ($reason -band 0x100) -or ($reason -band 0x200) ) {
              $name = $r.FileName
              if ([string]::IsNullOrWhiteSpace($name)) { continue }
              $path = "$drive`:\$name"
              $deleted += [pscustomobject]@{
                path = Normalize-Path $path
                time = try { $r.TimeStamp } catch { Get-Date }
              }
            }
          }
        } else {
          Write-Warn "Get-ForensicUSNRecord not found in PowerForensics â€“ skipping USN for $drive"
        }
      } catch {
        Write-Warn "USN read failed on $drive`: $($_.Exception.Message)"
      }
    }
  } else {
    # Sysmon Fallback (ID 23)
    try {
      $sysmon = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
      if ($sysmon -and $sysmon.IsEnabled) {
        $flt = @{ LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 23; StartTime = $BootTime }
        Get-WinEvent -FilterHashtable $flt -ErrorAction Stop | ForEach-Object {
          $m = [regex]::Match($_.Message, '(?im)TargetFilename:\s*(.+)')
          if ($m.Success) {
            $deleted += [pscustomobject]@{
              path = Normalize-Path $m.Groups[1].Value.Trim()
              time = $_.TimeCreated
            }
          }
        }
      } else {
        Write-Warn "Sysmon not available; deletion tracking may be empty."
      }
    } catch {
      Write-Warn "Sysmon deletion read failed: $($_.Exception.Message)"
    }
  }

  return ,$deleted
}

$DeletedEntries = Get-DeletedEntries

# Build Executed+Deleted pairs
$ExecDel = @()
if ($ExecutedMap.Count -gt 0 -and $DeletedEntries.Count -gt 0) {
  # Normalize by lower-case key for matching
  $execIndex = @{}
  foreach ($k in $ExecutedMap.Keys) {
    $execIndex[$k.ToLowerInvariant()] = $ExecutedMap[$k]
  }
  foreach ($d in $DeletedEntries) {
    $k = ($d.path ?? "").ToLowerInvariant()
    if ($execIndex.ContainsKey($k)) {
      $ExecDel += [pscustomobject]@{
        path = $d.path
        executedAt = $execIndex[$k]
        deletedAt  = $d.time
      }
    }
  }
}

# ---------------- PCASVC strings dump and filtering ----------------

function Get-PcaSvcPid {
  try {
    $svc = Get-CimInstance Win32_Service -Filter "Name='PcaSvc'"
    if ($svc -and $svc.ProcessId -gt 0) { return $svc.ProcessId }
  } catch {}
  return $null
}

function Get-StringsFromPid {
  param(
    [Parameter(Mandatory)][int]$Pid,
    [string]$StringsPath = ".\strings.exe"
  )
  $lines = @()
  if (-not (Test-Path $StringsPath)) {
    # try PATH
    $cmd = Get-Command strings.exe -ErrorAction SilentlyContinue
    if ($cmd) { $StringsPath = $cmd.Path }
  }
  if (-not (Test-Path $StringsPath)) {
    Write-Warn "strings.exe not found â€“ skipping PCASVC memory strings"
    return ,$lines
  }

  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $StringsPath
    $psi.Arguments = "-nobanner -pid $Pid"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) {
      Write-Warn "strings.exe exited with code $($p.ExitCode). stderr: $stderr"
    }
    if ($stdout) {
      $lines = $stdout -split "`r?`n" | Where-Object { $_ -and $_.Length -lt 4096 }
    }
  } catch {
    Write-Warn "Failed running strings.exe: $($_.Exception.Message)"
  }
  return ,$lines
}

$PcaSvcPid = Get-PcaSvcPid
$PcaStrings = @()
if ($PcaSvcPid) {
  Write-Info "Dumping strings from PcaSvc (PID $PcaSvcPid)"
  $PcaStrings = Get-StringsFromPid -Pid $PcaSvcPid -StringsPath $StringsExePath
} else {
  Write-Warn "PcaSvc is not running or PID not found; skipping memory strings"
}

# Extract file-like paths from strings
$CandidatePaths = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
$CleaningHits   = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)

$cleanRegex = [regex]'(?i)\b(clean|cleanup|wipe|wiper|delete\s+traces|remove|purge|scrub|erase|secure\s*delete)\b'

foreach ($line in $PcaStrings) {
  if ([string]::IsNullOrWhiteSpace($line)) { continue }

  if ($cleanRegex.IsMatch($line)) {
    $CleaningHits.Add($line.Trim()) | Out-Null
  }

  # Prefer quoted paths first
  $m = [regex]::Matches($line, '(?i)"([A-Z]:\\[^"]+)"')
  foreach ($mm in $m) {
    $p = Normalize-Path $mm.Groups[1].Value
    if ($p) { $CandidatePaths.Add($p) | Out-Null }
  }

  # Then unquoted path-looking tokens; allow spaces by consuming until a forbidden char
  $m2 = [regex]::Matches($line, '(?i)\b([A-Z]:\\[^"<>|]+?)(?=\s|$)')
  foreach ($mm in $m2) {
    $p = Normalize-Path $mm.Groups[1].Value.Trim()
    if ($p) { $CandidatePaths.Add($p) | Out-Null }
  }
}

# Build executed set for non-C: filtering
$ExecutedSet = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($k in $ExecutedMap.Keys) { $ExecutedSet.Add($k) | Out-Null }

# Evaluate candidates with filters (ONLY keep filtered ones)
$PcaFindings = @()
foreach ($path in $CandidatePaths) {
  try {
    if (-not (Test-Path $path)) { continue }

    $flags = @()

    # 1) No digital signature
    $valid = Has-ValidSignature $path
    if (-not $valid) { $flags += "NoSignature" }

    # 2) Not safe (detected by Defender earlier)
    if ($WinDefendPathsSet.Contains($path)) { $flags += "DefenderDetection" }

    # 3) Executed from drives other than C:\
    if ($path -match '^(?i)[D-Z]:\\' -and $ExecutedSet.Contains($path)) {
      $flags += "ExecutedOutsideC"
    }

    if ($flags.Count -gt 0) {
      $PcaFindings += [pscustomobject]@{
        path   = $path
        flags  = $flags
      }
    }
  } catch {}
}

# ---------------- Overview Numbers ----------------

$detectionsCount = ($WinDefendFindings.Count) + ($PcaFindings.Count)
$warningsCount   = ($CleaningHits.Count) + ($WarnProcessCount - ($ProcStates | Where-Object color -eq 'red' | Measure-Object).Count) # yellow-ish count approximation
$infoCount       = 0
$totalLogs       = $detectionsCount + $warningsCount + $infoCount

# ---------------- Data Model for HTML ----------------

$DATA = [ordered]@{
  generatedAt = (Get-Date)
  overview    = [ordered]@{
    detections = $detectionsCount
    warnings   = $warningsCount
    information= $infoCount
    total      = $totalLogs
  }
  generalInfo = $GeneralInfo
  winDefend   = $WinDefendFindings
  pcasvc      = [ordered]@{
    files    = $PcaFindings
    cleaning = @($CleaningHits)
  }
  execDeleted = $ExecDel
}

# ---------------- Output: HTML + CSS ----------------

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$templatePath = Join-Path $PSScriptRoot "template.html"
$cssSrcPath   = Join-Path $PSScriptRoot "style.css"

if (-not (Test-Path $templatePath)) {
  Write-Err "template.html not found next to script."
  exit 2
}
if (-not (Test-Path $cssSrcPath)) {
  Write-Err "style.css not found next to script."
  exit 3
}

$html = Get-Content $templatePath -Raw
$json = $DATA | ConvertTo-Json -Depth 8 -Compress

# Embed JSON into the template at the marker /*__DATA__*/
$html = $html -replace '/\*__DATA__\*/', ("window.__DATA__ = " + $json + ";")

# Write files
$reportHtmlPath = Join-Path $OutputDir "report.html"
$reportCssPath  = Join-Path $OutputDir "style.css"

Set-Content -Path $reportHtmlPath -Value $html -Encoding UTF8
Copy-Item -Path $cssSrcPath -Destination $reportCssPath -Force

Write-OK "Report written to: $reportHtmlPath"

# ---------------- Discord Upload ----------------

function Send-FileToDiscord {
  param(
    [Parameter(Mandatory)][string]$Webhook,
    [Parameter(Mandatory)][string]$FilePath,
    [string]$Message = ""
  )
  try {
    $form = @{
      "file1"  = Get-Item -Path $FilePath
      "content" = $Message
    }
    Invoke-RestMethod -Uri $Webhook -Method Post -Form $form | Out-Null
    Write-OK "Uploaded: $([IO.Path]::GetFileName($FilePath))"
  } catch {
    Write-Err "Discord upload failed: $($_.Exception.Message)"
  }
}

if ($WebhookUrl) {
  # Always upload the HTML
  Send-FileToDiscord -Webhook $WebhookUrl -FilePath $reportHtmlPath -Message "Scan report (HTML)."

  if ($ZipAndUpload) {
    $zipPath = Join-Path $OutputDir "report_bundle.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path (Join-Path $OutputDir "*") -DestinationPath $zipPath
    Send-FileToDiscord -Webhook $WebhookUrl -FilePath $zipPath -Message "Report bundle (HTML + CSS)."
  }
} else {
  Write-Warn "WebhookUrl not provided; skipping Discord upload."
}

Write-OK "Done."
