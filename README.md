# 🛠️ KISA 기반 Windows Incident Response Toolkit

## 개요
이 저장소는「KISA 침해사고 분석 절차 안내서 (2010-8호)」와 
「정보통신분야 침해사고 대응 안내서 (2024.09)」에서 제시한  
점검 항목과 예시 명령을 바탕으로, Windows 환경 침해사고 초동 대응 및 아티팩트 수집을  
자동화한 PowerShell 스크립트 모음입니다.  

문서에 언급된 netstat, tasklist, Winlogon-Autoruns, IIS 로그, 이벤트 로그 등  
주요 점검 포인트를 Windows PowerShell cmdlet과 고전 명령을 병행하여 수집하도록 설계했습니다.  

---

## 📂 폴더 구조
kisa-windows-ir/

├── README.md

├── LICENSE

├── scripts/

│ ├── ir-collect.ps1 # 정식·상세 수집 스크립트 (풀셋)

│ └── ir-quick.ps1 # 신속·간이 수집 스크립트 (핵심셋)

└── outputs/ # 샘플 산출물 (선택적, .gitkeep 포함)


---

## ⚙️ 요구 사항
- **지원 OS**: Windows 10/11, Windows Server 2016 이상  
- **PowerShell**: 5.1 이상 (또는 PowerShell 7.x 이상)  
- **권한**: 관리자 권한 실행 권장  
- **디스크 여유 공간**: 이벤트/IIS 로그 크기에 따라 수백 MB 이상 필요할 수 있음  

---

## 🚀 사용 방법
1. 저장소 클론:
   ```powershell
   git clone https://github.com/<your-username>/kisa-windows-ir.git
   cd kisa-windows-ir/scripts

2. 스크립트 실행 (예: 상세 수집):
   ```powershell
   .\ir-collect.ps1 -CasePath "C:\IR_Case01" -Days 7 -Zip

### 주요 인자 설명

| 인자 | 설명 | 기본값 / 예시 |
|------|------|----------------|
| `-CasePath` | 결과 저장 경로 지정 | `C:\IR_Case01` |
| `-Days` | 최근 이벤트 로그 수집 기간 | 7일 |
| `-Zip` | 결과를 압축(zip) 파일로 저장 | 사용 시 zip 생성 |


3. 신속 수집(핵심 아티팩트만):
   ```powershell
   .\ir-quick.ps1 -CasePath "C:\IR_Case01"
