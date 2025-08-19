[CmdletBinding()]
param([string]$OutRoot="$env:SystemDrive\IR")   # 출력 루트 (기본 C:\IR)

Set-StrictMode -Version Latest
$case = Join-Path $OutRoot ("IR_Quick_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
New-Item -ItemType Directory -Force -Path $case | Out-Null   # 결과 저장 폴더 생성

# 타임스탬프 기록
Get-Date | Out-File -FilePath (Join-Path $case "timestamp.txt")

# CPU 사용량 기준 상위 40개 프로세스 목록
Get-Process | Sort-Object CPU -Descending | Select-Object -First 40 Id,Name,CPU,StartTime,Path |
  Export-Csv (Join-Path $case "top_processes.csv") -NoTypeInformation -Encoding UTF8

# 네트워크 연결(리스닝/Established 상태)
Get-NetTCPConnection -State Listen,Established | 
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
  Export-Csv (Join-Path $case "net.csv") -NoTypeInformation -Encoding UTF8

# 예약 작업(Task Scheduler) 단순 목록
Get-ScheduledTask | Select-Object TaskPath,TaskName |
  Export-Csv (Join-Path $case "tasks.csv") -NoTypeInformation -Encoding UTF8

# 실행 중인 서비스
Get-Service | Where-Object {$_.Status -eq "Running"} |
  Select-Object Name,DisplayName,StartType |
  Export-Csv (Join-Path $case "running_services.csv") -NoTypeInformation -Encoding UTF8

# Winlogon Shell 값 확인 (지속성 공격 여부 파악)
(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon').Shell |
  Out-File (Join-Path $case "winlogon_shell.txt")

Write-Host "[+] Saved: $case"