[CmdletBinding()]
param(
  [string]$OutRoot = "$env:SystemDrive\IR",   # 출력 경로 기본값: C:\IR
  [int]$Days = 7,                             # 이벤트 로그 수집 기간 (최근 7일)
  [switch]$Zip,                               # 결과를 ZIP으로 압축할지 여부
  [switch]$NoHeavy                            # 무거운 작업(파일 전체 스냅샷) 제외 여부
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# 새로운 IR(Incident Response) 케이스 폴더 생성
function New-IRCase {
  param([string]$Root)
  $ts = Get-Date -Format "yyyyMMdd_HHmmss"   # 현재 시간으로 폴더명 생성
  $case = Join-Path $Root ("IR_" + $ts)
  New-Item -ItemType Directory -Force -Path $case | Out-Null
  # 하위 디렉터리 구조 생성 (system, network, process 등 카테고리별)
  foreach($d in "system","network","process","services","tasks","drivers","persistence","users","events","apps","fs","logs"){
    New-Item -ItemType Directory -Force -Path (Join-Path $case $d) | Out-Null
  }
  return $case
}

# 객체 데이터를 JSON/CSV 두 가지 형식으로 저장하는 함수
function Out-JsonCsv {
  param([Parameter(Mandatory)][Object]$Data,[Parameter(Mandatory)][string]$BasePath)
  $json = $BasePath + ".json"
  $csv  = $BasePath + ".csv"
  try { $Data | ConvertTo-Json -Depth 6 | Out-File -FilePath $json -Encoding UTF8 } catch {}
  try { $Data | Export-Csv -Path $csv -NoTypeInformation -Force -Encoding UTF8 } catch {}
}

$CasePath = New-IRCase -Root $OutRoot   # 분석 케이스 폴더 생성

# 1) 시스템 정보 수집
$sysInfo = [ordered]@{
  ComputerName = $env:COMPUTERNAME
  Timestamp    = (Get-Date).ToString("o")
  OS           = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, InstallDate, LastBootUpTime)
  BIOS         = (Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, SerialNumber, ReleaseDate)
  CPU          = (Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed)
  RAMGB        = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,2)
  TimeZone     = (Get-TimeZone).Id
  UptimeHours  = [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours,2)
}
Out-JsonCsv -Data $sysInfo -BasePath (Join-Path $CasePath "system\system_info")

# 2) 네트워크 정보 (인터페이스, 라우팅, 포트 등)
$ifcfg = Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv6Address,DNSServer,InterfaceDescription
Out-JsonCsv -Data $ifcfg -BasePath (Join-Path $CasePath "network\interfaces")
try { ipconfig /all | Out-File (Join-Path $CasePath "network\ipconfig_all.txt") -Encoding UTF8 } catch {}
try { arp -a | Out-File (Join-Path $CasePath "network\arp.txt") -Encoding UTF8 } catch {}
try { route print | Out-File (Join-Path $CasePath "network\route.txt") -Encoding UTF8 } catch {}
try { Get-DnsClientCache | Out-JsonCsv -BasePath (Join-Path $CasePath "network\dns_cache") } catch {}
try {
  Get-NetTCPConnection -State Established,Listen | 
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
    Sort-Object LocalPort |
    Out-JsonCsv -BasePath (Join-Path $CasePath "network\net_tcp")
} catch {}

# 3) 프로세스 목록
$procs = Get-CimInstance Win32_Process | 
  Select-Object ProcessId, Name, CommandLine, CreationDate, ExecutablePath, HandleCount, ThreadCount, WorkingSetSize, ParentProcessId
Out-JsonCsv -Data $procs -BasePath (Join-Path $CasePath "process\processes")

# 4) 서비스 및 드라이버
try { Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceType | Out-JsonCsv -BasePath (Join-Path $CasePath "services\services") } catch {}
try { Get-CimInstance Win32_SystemDriver | Select-Object Name, State, StartMode, PathName | Out-JsonCsv -BasePath (Join-Path $CasePath "drivers\drivers") } catch {}

# 5) 예약 작업(Scheduled Tasks)
try {
  Get-ScheduledTask | ForEach-Object {
    $ti = $_ | Get-ScheduledTaskInfo
    [pscustomobject]@{
      TaskName = $_.TaskName
      TaskPath = $_.TaskPath
      State    = $ti.State
      LastRun  = $ti.LastRunTime
      NextRun  = $ti.NextRunTime
      Actions  = ($_.Actions | ForEach-Object {$_.Execute + " " + $_.Arguments}) -join "; "
      Triggers = ($_.Triggers | ForEach-Object { $_.ToString() }) -join "; "
    }
  } | Out-JsonCsv -BasePath (Join-Path $CasePath "tasks\scheduled_tasks")
} catch {}

# 6) Persistence (지속성 점검)
function Get-RegistryValues {
  param([string]$Path)
  try {
    # 지정한 레지스트리 경로의 값들을 가져옴
    $values = Get-ItemProperty -LiteralPath $Path | Select-Object * -ExcludeProperty PS*,Property
    $props = @()
    foreach($p in $values.PSObject.Properties){ 
      if($p.Name -notmatch '^PS'){$props += [pscustomobject]@{Name=$p.Name; Value=$p.Value} } 
    }
    return $props
  } catch { return @() } # 오류 발생 시 빈 배열 반환
}

$persist = @()
# 자동 실행 관련 Run/RunOnce 레지스트리 키 확인 (시작 프로그램 등록 여부)
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

# IFEO (Image File Execution Options) Debugger 확인
# 악성코드가 정상 프로그램 대신 실행되도록 등록했는지 점검
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
try {
  Get-ChildItem -Path $ifeo -ErrorAction Stop | ForEach-Object {
    $debugger = (Get-ItemProperty -Path $_.PsPath -ErrorAction SilentlyContinue).Debugger
    if($debugger){ $persist += [pscustomobject]@{Location=$_.PsPath; Name='Debugger'; Data=$debugger} }
  }
} catch {}

# AppInit_DLLs, Winlogon 키 확인 (시스템 부팅 시 DLL, Userinit, Shell 등 실행 여부)
$persist += (Get-RegistryValues -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' | Where-Object {$_.Name -match 'AppInit_DLLs|LoadAppInit_DLLs'} | ForEach-Object {[pscustomobject]@{Location='...Windows'; Name=$_.Name; Data=$_.Value}})
$persist += (Get-RegistryValues -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | Where-Object {$_.Name -match 'Userinit|Shell|Notify'} | ForEach-Object {[pscustomobject]@{Location='...Winlogon'; Name=$_.Name; Data=$_.Value}})

# 시작 프로그램 폴더 점검
$startupPaths = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
foreach($sp in $startupPaths){
  if(Test-Path $sp){
    Get-ChildItem $sp -Force | ForEach-Object {
      $persist += [pscustomobject]@{Location=$sp; Name=$_.Name; Data=$_.FullName}
    }
  }
}
Out-JsonCsv -Data $persist -BasePath (Join-Path $CasePath "persistence\persistence_points")

# 7) Users / Sessions (사용자·세션 점검)
# 로컬 사용자 계정 목록 수집
try { Get-LocalUser | Select-Object Name,Enabled,LastLogon | Out-JsonCsv -BasePath (Join-Path $CasePath "users\local_users") } catch {}
# 로컬 Administrators 그룹 구성원 수집
try { Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object Name, ObjectClass, PrincipalSource | Out-JsonCsv -BasePath (Join-Path $CasePath "users\local_admins") } catch {}
# 현재 로그인 세션 정보(quser 명령어 출력)
try { quser | Out-File -FilePath (Join-Path $CasePath "users\quser.txt") -Encoding UTF8 } catch {}

# 8) Installed Apps (설치된 프로그램 목록)
try {
  Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* , HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*  -ErrorAction SilentlyContinue |
          Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
          Out-JsonCsv -BasePath (Join-Path $CasePath "apps\installed_programs")
} catch {}

# 9) Events (최근 $Days 일 이벤트 로그)
$since = (Get-Date).AddDays(-$Days)
function Dump-WinEvent {
  param([string]$LogName,[string]$OutBase)
  try {
    Get-WinEvent -FilterHashtable @{LogName=$LogName; StartTime=$since} -ErrorAction Stop |
      Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message |
      Out-JsonCsv -BasePath $OutBase
  } catch {}
}
# 주요 로그(System, Application, Security, PowerShell, Sysmon) 수집
Dump-WinEvent -LogName "System"      -OutBase (Join-Path $CasePath "events\system")
Dump-WinEvent -LogName "Application" -OutBase (Join-Path $CasePath "events\application")
Dump-WinEvent -LogName "Security"    -OutBase (Join-Path $CasePath "events\security")
Dump-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -OutBase (Join-Path $CasePath "events\powershell")
try {
  if(Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue){
    Dump-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -OutBase (Join-Path $CasePath "events\sysmon")
  }
} catch {}

# 10) File snapshot (파일 스냅샷, 옵션)
if(-not $NoHeavy){
  $targets = @("$env:ProgramData","$env:ProgramFiles","$env:ProgramFiles(x86)","$env:PUBLIC\Downloads","$env:USERPROFILE\Downloads")
  $list = foreach($t in $targets){
    if(Test-Path $t){
      # 대상 폴더 내 모든 파일 목록(경로, 크기, 최종 수정 시간) 재귀 수집
      Get-ChildItem -Path $t -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTime
    }
  }
  Out-JsonCsv -Data $list -BasePath (Join-Path $CasePath "fs\files_snapshot")
}

# 11) Summary (요약 정보 저장)
$summary = @"
[IR Summary]
Host: $($sysInfo.ComputerName)
Time: $((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
Uptime(h): $($sysInfo.UptimeHours)
Collected: system, network, processes, services, drivers, tasks, persistence, users, apps, events, fs (optional)
"@
$summary | Out-File -FilePath (Join-Path $CasePath "IR_Summary.txt") -Encoding UTF8

# 결과를 압축(zip)으로 저장할 경우
if($Zip){
  $zipPath = Join-Path $CasePath "..\IR_Package_$((Split-Path $CasePath -Leaf)).zip"
  Compress-Archive -Path "$CasePath\*" -DestinationPath $zipPath -Force
}
Write-Host "[+] Saved: $CasePath"