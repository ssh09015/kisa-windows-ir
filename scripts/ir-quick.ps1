# =========================
# KISA 기반 Windows IR 수집 스크립트 (신속/간이)
# =========================
[CmdletBinding()]
param([string]$OutRoot="$env:SystemDrive\IR")   # 출력 루트(기본 C:\IR)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# 결과 폴더 생성
$case = Join-Path $OutRoot ("IR_Quick_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
New-Item -ItemType Directory -Force -Path $case | Out-Null

# 1) 타임스탬프
Get-Date | Out-File -FilePath (Join-Path $case "timestamp.txt") -Encoding UTF8

# 2) 상위 프로세스(대략적인 부하 확인)
try {
  Get-Process | Sort-Object CPU -Descending |
    Select-Object -First 40 Id,Name,CPU,StartTime,Path |
    Export-Csv (Join-Path $case "top_processes.csv") -NoTypeInformation -Encoding UTF8
} catch {}

# 3) TCP 연결(수신/설정)
try {
  Get-NetTCPConnection -State Listen,Established |
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
    Export-Csv (Join-Path $case "net.csv") -NoTypeInformation -Encoding UTF8
} catch {}

# 4) 예약 작업 목록(간단)
try {
  Get-ScheduledTask | Select-Object TaskPath,TaskName |
    Export-Csv (Join-Path $case "tasks.csv") -NoTypeInformation -Encoding UTF8
} catch {}

# 5) 실행 중 서비스
try {
  Get-Service | Where-Object {$_.Status -eq "Running"} |
    Select-Object Name,DisplayName,StartType |
    Export-Csv (Join-Path $case "running_services.csv") -NoTypeInformation -Encoding UTF8
} catch {}

# 6) Winlogon Shell 값(지속성 단서)
try {
  (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon').Shell |
    Out-File (Join-Path $case "winlogon_shell.txt")
} catch {}

Write-Host "[+] Saved: $case"