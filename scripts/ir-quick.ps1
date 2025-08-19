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

# 2) 상위 프로세스(안전한 정렬: CPU 초 단위로 변환 후 정렬)
try {
  $top = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    # CPU 값이 없거나 타입이 다른 경우를 대비해 안전하게 숫자(초)로 환산
    $cpuSec = 0
    try {
      if ($_.CPU -ne $null) {
        $cpuSec = [double]$_.CPU
      } elseif ($_.TotalProcessorTime) {
        $cpuSec = [double]$_.TotalProcessorTime.TotalSeconds
      }
    } catch { $cpuSec = 0 }

    # 일부 속성은 접근 권한/종료 타이밍 때문에 예외가 날 수 있어 보호
    $start = $null; $path = $null
    try { $start = $_.StartTime } catch {}
    try { $path  = $_.Path }      catch {}

    [pscustomobject]@{
      Id         = $_.Id
      Name       = $_.Name
      CPUSeconds = [math]::Round($cpuSec, 2)
      StartTime  = $start
      Path       = $path
    }
  } | Sort-Object CPUSeconds -Descending | Select-Object -First 40

  $top | Export-Csv (Join-Path $case "top_processes.csv") -NoTypeInformation -Encoding UTF8
} catch {}

# 3) TCP 연결(수신/설정)
try {
  Get-NetTCPConnection -State Listen,Established -ErrorAction SilentlyContinue |
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
