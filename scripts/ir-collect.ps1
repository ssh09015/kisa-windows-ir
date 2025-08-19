# =========================
# KISA 기반 Windows IR 수집 스크립트 (정식/상세)
# =========================
[CmdletBinding()]
param(
  [string]$OutRoot = "$env:SystemDrive\IR",   # 출력 루트 기본값: C:\IR
  [int]$Days = 7,                             # 이벤트 로그 수집 기간(최근 N일)
  [switch]$Zip,                               # 결과를 ZIP으로 압축할지 여부
  [switch]$NoHeavy                            # 무거운 작업(대규모 파일 스냅샷) 제외
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ---- 공용 유틸 ----
function New-IRCase {
  param([string]$Root)
  # IR_<타임스탬프> 폴더를 생성한다
  $ts = Get-Date -Format "yyyyMMdd_HHmmss"
  $case = Join-Path $Root ("IR_" + $ts)
  New-Item -ItemType Directory -Force -Path $case | Out-Null

  # 하위 카테고리 폴더를 생성한다
  foreach($d in "system","network","process","services","tasks","drivers","persistence","users","events","apps","fs","logs"){
    New-Item -ItemType Directory -Force -Path (Join-Path $case $d) | Out-Null
  }
  return $case
}

function Out-JsonCsv {
  param(
    [Parameter(Mandatory)][Object]$Data,      # 내보낼 객체(컬렉션 가능)
    [Parameter(Mandatory)][string]$BasePath   # 확장자 제외한 경로(동시에 .json / .csv 생성)
  )
  $json = $BasePath + ".json"
  $csv  = $BasePath + ".csv"
  try { $Data | ConvertTo-Json -Depth 6 | Out-File -FilePath $json -Encoding UTF8 } catch {}
  try { $Data | Export-Csv -Path $csv -NoTypeInformation -Force -Encoding UTF8 } catch {}
}

# 케이스 폴더 생성
$CasePath = New-IRCase -Root $OutRoot

# -------------------------------
# 1) System(시스템 기본정보)
# -------------------------------
try {
  $os  = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, InstallDate, LastBootUpTime
  $cs  = Get-CimInstance Win32_ComputerSystem
  $cpu = Get-CimInstance Win32_Processor       | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
  $bios= Get-CimInstance Win32_BIOS            | Select-Object Manufacturer, SMBIOSBIOSVersion, SerialNumber, ReleaseDate

  $sysInfo = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = (Get-Date).ToString("o")
    OS           = $os
    BIOS         = $bios
    CPU          = $cpu
    RAMGB        = [math]::Round(($cs.TotalPhysicalMemory/1GB),2)
    TimeZone     = (Get-TimeZone).Id
    UptimeHours  = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours,2)
  }
  Out-JsonCsv -Data $sysInfo -BasePath (Join-Path $CasePath "system\system_info")
} catch {}

# -------------------------------
# 2) Network(인터페이스/연결/캐시)
# -------------------------------
try {
  $ifcfg = Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv6Address,DNSServer,InterfaceDescription
  Out-JsonCsv -Data $ifcfg -BasePath (Join-Path $CasePath "network\interfaces")
} catch {}

try { ipconfig /all | Out-File -FilePath (Join-Path $CasePath "network\ipconfig_all.txt") -Encoding UTF8 } catch {}
try { arp -a         | Out-File -FilePath (Join-Path $CasePath "network\arp.txt")          -Encoding UTF8 } catch {}
try { route print    | Out-File -FilePath (Join-Path $CasePath "network\route.txt")        -Encoding UTF8 } catch {}

try {
  if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
    $dns = Get-DnsClientCache
    Out-JsonCsv -Data $dns -BasePath (Join-Path $CasePath "network\dns_cache")
  }
} catch {}

try {
  $tcps = Get-NetTCPConnection -State Established,Listen |
          Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
          Sort-Object LocalPort
  Out-JsonCsv -Data $tcps -BasePath (Join-Path $CasePath "network\net_tcp")
} catch {}

try {
  $procPorts = Get-Process | Select-Object Id,Name,Path |
    ForEach-Object {
      $listens = (Get-NetTCPConnection -OwningProcess $_.Id -ErrorAction SilentlyContinue |
                 Where-Object {$_.State -eq "Listen"} |
                 Select-Object -ExpandProperty LocalPort -Unique)
      $_ | Add-Member -NotePropertyName "ListeningPorts" -NotePropertyValue ($listens -join ",") -PassThru
    }
  Out-JsonCsv -Data $procPorts -BasePath (Join-Path $CasePath "network\proc_ports")
} catch {}

# -------------------------------
# 3) Processes(프로세스)
# -------------------------------
try {
  $procs = Get-CimInstance Win32_Process |
    Select-Object ProcessId, Name, CommandLine, CreationDate, ExecutablePath, HandleCount, ThreadCount, WorkingSetSize, ParentProcessId
  Out-JsonCsv -Data $procs -BasePath (Join-Path $CasePath "process\processes")
} catch {}

# -------------------------------
# 4) Services / Drivers
# -------------------------------
try {
  $svc = Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceType
  Out-JsonCsv -Data $svc -BasePath (Join-Path $CasePath "services\services")
} catch {}

try {
  $drv = Get-CimInstance Win32_SystemDriver | Select-Object Name, State, StartMode, PathName
  Out-JsonCsv -Data $drv -BasePath (Join-Path $CasePath "drivers\drivers")
} catch {}

# -------------------------------
# 5) Scheduled Tasks(예약 작업)
# -------------------------------
try {
  $tasks = Get-ScheduledTask | ForEach-Object {
    $ti = $_ | Get-ScheduledTaskInfo
    [pscustomobject]@{
      TaskName = $_.TaskName
      TaskPath = $_.TaskPath
      State    = $ti.State
      LastRun  = $ti.LastRunTime
      NextRun  = $ti.NextRunTime
      Actions  = ($_.Actions  | ForEach-Object {($_.Execute + " " + $_.Arguments).Trim()}) -join "; "
      Triggers = ($_.Triggers | ForEach-Object {$_.ToString()}) -join "; "
    }
  }
  Out-JsonCsv -Data $tasks -BasePath (Join-Path $CasePath "tasks\scheduled_tasks")
} catch {}

# -------------------------------
# 6) Persistence(지속성 지점)
# -------------------------------
function Get-RegistryValues {
  param([string]$Path)
  try {
    $values = Get-ItemProperty -LiteralPath $Path | Select-Object * -ExcludeProperty PS*,Property
    $props = @()
    foreach($p in $values.PSObject.Properties){
      if($p.Name -notmatch '^PS'){ $props += [pscustomobject]@{Name=$p.Name; Value=$p.Value} }
    }
    return $props
  } catch { return @() }
}

$persist = @()

# Run / RunOnce
$runKeys = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach($rk in $runKeys){
  foreach($v in Get-RegistryValues -Path $rk){
    $persist += [pscustomobject]@{Location=$rk; Name=$v.Name; Data=$v.Value}
  }
}

# IFEO Debugger
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
try {
  Get-ChildItem -Path $ifeo -ErrorAction Stop | ForEach-Object {
    $debugger = (Get-ItemProperty -Path $_.PsPath -ErrorAction SilentlyContinue).Debugger
    if($debugger){ $persist += [pscustomobject]@{Location=$_.PsPath; Name='Debugger'; Data=$debugger} }
  }
} catch {}

# AppInit_DLLs / Winlogon(Userinit/Shell/Notify)
$persist += (Get-RegistryValues -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' |
            Where-Object {$_.Name -match 'AppInit_DLLs|LoadAppInit_DLLs'} |
            ForEach-Object {[pscustomobject]@{Location='...Windows'; Name=$_.Name; Data=$_.Value}})

$persist += (Get-RegistryValues -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' |
            Where-Object {$_.Name -match 'Userinit|Shell|Notify'} |
            ForEach-Object {[pscustomobject]@{Location='...Winlogon'; Name=$_.Name; Data=$_.Value}})

# 시작프로그램 폴더
$startupPaths = @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
foreach($sp in $startupPaths){
  if(Test-Path $sp){
    Get-ChildItem $sp -Force | ForEach-Object {
      $persist += [pscustomobject]@{Location=$sp; Name=$_.Name; Data=$_.FullName}
    }
  }
}

try { Out-JsonCsv -Data $persist -BasePath (Join-Path $CasePath "persistence\persistence_points") } catch {}

# -------------------------------
# 7) Users / Sessions(계정/세션)
# -------------------------------
try {
  if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    $localUsers = Get-LocalUser | Select-Object Name,Enabled,LastLogon
    Out-JsonCsv -Data $localUsers -BasePath (Join-Path $CasePath "users\local_users")
  }
} catch {}

try {
  if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
              Select-Object Name, ObjectClass, PrincipalSource
    Out-JsonCsv -Data $admins -BasePath (Join-Path $CasePath "users\local_admins")
  }
} catch {}

try { quser | Out-File -FilePath (Join-Path $CasePath "users\quser.txt") -Encoding UTF8 } catch {}

# -------------------------------
# 8) Installed Apps(설치 프로그램)
# -------------------------------
try {
  $apps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* ,
                           HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*  -ErrorAction SilentlyContinue |
          Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
  Out-JsonCsv -Data $apps -BasePath (Join-Path $CasePath "apps\installed_programs")
} catch {}

# -------------------------------
# 9) Events(최근 N일)
# -------------------------------
$since = (Get-Date).AddDays(-$Days)

function Dump-WinEvent {
  param([string]$LogName,[string]$OutBase)
  try {
    $ev = Get-WinEvent -FilterHashtable @{LogName=$LogName; StartTime=$since} -ErrorAction Stop |
          Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message
    Out-JsonCsv -Data $ev -BasePath $OutBase
  } catch {}
}

Dump-WinEvent -LogName "System"      -OutBase (Join-Path $CasePath "events\system")
Dump-WinEvent -LogName "Application" -OutBase (Join-Path $CasePath "events\application")
Dump-WinEvent -LogName "Security"    -OutBase (Join-Path $CasePath "events\security")
Dump-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -OutBase (Join-Path $CasePath "events\powershell")

try {
  if (Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue) {
    Dump-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -OutBase (Join-Path $CasePath "events\sysmon")
  }
} catch {}

# -------------------------------
# 10) File snapshot(옵션, 무거움)
# -------------------------------
if(-not $NoHeavy){
  try {
    $targets = @("$env:ProgramData","$env:ProgramFiles","$env:ProgramFiles(x86)","$env:PUBLIC\Downloads","$env:USERPROFILE\Downloads")
    $list = foreach($t in $targets){
      if(Test-Path $t){
        Get-ChildItem -Path $t -File -Recurse -ErrorAction SilentlyContinue |
          Select-Object FullName, Length, LastWriteTime
      }
    }
    Out-JsonCsv -Data $list -BasePath (Join-Path $CasePath "fs\files_snapshot")
  } catch {}
}

# -------------------------------
# 11) Summary(요약)
# -------------------------------
$summary = @"
[IR Summary]
Host: $env:COMPUTERNAME
Time: $((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
Days: $Days
Collected: system, network, process, services, drivers, tasks, persistence, users, apps, events, fs$(if($NoHeavy){"(skipped)"}else{"(included)"})
"@
$summary | Out-File -FilePath (Join-Path $CasePath "IR_Summary.txt") -Encoding UTF8

# ZIP 옵션 처리
if($Zip){
  try {
    $zipPath = Join-Path $CasePath "..\IR_Package_$((Split-Path $CasePath -Leaf)).zip"
    Compress-Archive -Path "$CasePath\*" -DestinationPath $zipPath -Force
  } catch {}
}

Write-Host "[+] Saved: $CasePath"