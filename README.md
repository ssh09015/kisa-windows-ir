🛡️ KISA 기반 Windows Incident Response Toolkit

개요



이 저장소는 \*\*KISA 침해사고 분석 절차 안내서(2010-8호)\*\*와 \*\*정보통신분야 침해사고 대응 안내서(2024.09)\*\*에서 제시한 점검 항목과 예시 명령을 바탕으로 Windows 환경 침해사고 초동 대응·아티팩트 수집을 자동화한 PowerShell 스크립트 모음이다.

문서에 흩어져 있는 netstat, tasklist, Winlogon·Autoruns 지점, IIS 로그, 이벤트 로그 등 점검 포인트를 현행 Windows에 맞춘 cmdlet과 고전 명령을 병행해 수집하도록 설계했다.



폴더 구조

kisa-windows-ir/

├─ README.md

├─ LICENSE

├─ scripts/

│  ├─ ir-collect.ps1        # 정식·상세 수집 스크립트(풀셋)

│  └─ ir-quick.ps1          # 신속·간이 수집 스크립트(핵심셋)

└─ outputs/                 # 샘플 산출물(선택)



요구 사항



지원 OS: Windows 10/11, Windows Server 2016 이상 권장이다



PowerShell: 5.1 이상(또는 PowerShell 7.x)이다



권한: 관리자 권한 실행 권장이다



디스크 여유 공간: 이벤트·IIS 로그 규모에 따라 수백 MB 이상 필요할 수 있다



선택 도구(있을 때만 자동 수집한다): Sysinternals autorunsc.exe, handle.exe, tcpvcon.exe 등이다



빠른 시작

정식·상세 수집

\# 관리자 권한 PowerShell

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\\scripts\\ir-collect.ps1 -OutRoot 'C:\\IR' -Days 7 -Zip





주요 파라미터:



-OutRoot: 산출물 루트 디렉터리이다(기본 C:\\IR)



-Days: 이벤트 로그 수집 기간이다(기본 7일)



-Zip: 수집 결과를 ZIP으로 추가 압축한다



-NoHeavy: 대용량 파일 스냅샷 단계 생략 플래그이다



신속·간이 수집

.\\scripts\\ir-quick.ps1 -OutRoot 'C:\\IR'



수집 항목 개요

ir-collect.ps1 (풀셋)



System: OS/BIOS/CPU/RAM/업타임/타임존 요약이다



Network: 인터페이스, ipconfig/arp/route, DNS 캐시, Get-NetTCPConnection 연결, 고전 netstat -an/-ano/-ab/-s 출력이다



Process: WMI 프로세스 상세(명령행·PPID·경로 등), tasklist /svc, tasklist /m, wmic process list brief이다



Services/Drivers: 서비스 상태, 커널 드라이버 상태이다



Scheduled Tasks: 작업 경로·상태·트리거·실행 커맨드이다



Persistence: Run/RunOnce, IFEO(Debugger), Winlogon(Shell/Userinit/Notify), AppInit\_DLLs, 시작폴더, autorunsc.exe CSV(존재 시)이다



Users/Sessions: 로컬 계정, 로컬 Administrators, quser, whoami /all이다



Installed Apps: Uninstall 키 기반 설치 목록이다



Events: 최근 N일 System/Application/Security/PowerShell, 존재 시 Sysmon까지이다(+ 예시로 wevtutil 특정 쿼리 포함 가능하다)



File Snapshot(선택): ProgramFiles·Downloads 등 경로 파일 목록이다



IIS Logs(선택 섹션 구성 가능): 기본 로그 루트 존재 시 목록화한다



Summary: 수집 범위 요약 텍스트이다



ir-quick.ps1 (핵심셋)



상위 CPU 프로세스 Top 40이다



리스닝·Established 연결이다



예약 작업 간단 목록이다



실행 중 서비스이다



HKLM\\...\\Winlogon\\Shell 값이다



산출물 구조 예시

C:\\IR\\IR\_YYYYMMDD\_HHMMSS\\

├─ system\\system\_info.json|csv

├─ network\\

│  ├─ interfaces.json|csv

│  ├─ ipconfig\_all.txt, arp.txt, route.txt

│  ├─ dns\_cache.json|csv

│  ├─ net\_tcp.json|csv

│  └─ netstat\_an.txt / netstat\_ano.txt / netstat\_ab.txt / netstat\_s.txt

├─ process\\

│  ├─ processes.json|csv

│  ├─ tasklist\_svc.txt

│  └─ tasklist\_modules.txt

├─ services\\services.json|csv

├─ drivers\\drivers.json|csv

├─ tasks\\scheduled\_tasks.json|csv

├─ persistence\\

│  ├─ persistence\_points.json|csv

│  ├─ reg\_winlogon\_notify.txt

│  ├─ reg\_appinit.txt

│  └─ autoruns.csv            # autorunsc.exe 있을 때만 생성한다

├─ users\\

│  ├─ local\_users.json|csv

│  ├─ local\_admins.json|csv

│  ├─ quser.txt

│  └─ whoami\_all.txt

├─ apps\\installed\_programs.json|csv

├─ events\\

│  ├─ system.json|csv

│  ├─ application.json|csv

│  ├─ security.json|csv

│  ├─ powershell.json|csv

│  └─ sysmon.json|csv         # 로그 존재 시 생성한다

├─ fs\\files\_snapshot.json|csv  # -NoHeavy 미지정 시

└─ IR\_Summary.txt

