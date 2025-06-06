# Exception Reporter

Exception Reporter는 Windows 애플리케이션 실행 중 발생하는 예외를 자동으로 감지하고 상세한 로그 파일을 생성하는 라이브러리입니다. 

프로그램 크래시 디버깅과 진단을 위한 유용한 도구로 활용할 수 있습니다.

[영상 링크](https://www.youtube.com/watch?v=r9DUcUXM5y8)

![Image](https://github.com/user-attachments/assets/ce27900a-ec79-4770-84e7-308d4d34554d)

```
=== Exception Report ===
Process ID: 20168
Thread ID: 18008
Exception Code: 0xc0000005 (EXCEPTION_ACCESS_VIOLATION - Writing at address 0x0)
Exception Address: 0x00007FF6BA09472C

=== Register State ===
RAX: 0x0
RBX: 0x0
RCX: 0x88
RDX: 0x7ff6ba09fdd0
RSI: 0x0
RDI: 0xcbffaff948
R8:  0x3
R9:  0xcbffaff048
R10: 0x14
R11: 0x246
R12: 0x0
R13: 0x0
R14: 0x0
R15: 0x0
RIP: 0x7ff6ba09472c
RSP: 0xcbffaff420
RBP: 0xcbffaff440

=== Stack Trace ===
Stack trace:
0x7ff6ba09472c: TestApplication.exe+1472c TriggerAccessViolation at C:\Users\Kisu\Desktop\TestApplication\TestApplication\TestApplication.cpp:13
0x7ff6ba09463b: TestApplication.exe+1463b ExecuteSEHTest at C:\Users\Kisu\Desktop\TestApplication\TestApplication\TestApplication.cpp:53
0x7ff6ba095c65: TestApplication.exe+15c65 main at C:\Users\Kisu\Desktop\TestApplication\TestApplication\TestApplication.cpp:89
0x7ff6ba096bf9: TestApplication.exe+16bf9 invoke_main at D:\a\_work\1\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:79
0x7ff6ba096aa2: TestApplication.exe+16aa2 __scrt_common_main_seh at D:\a\_work\1\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:288
0x7ff6ba09695e: TestApplication.exe+1695e __scrt_common_main at D:\a\_work\1\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:331
0x7ff6ba096c8e: TestApplication.exe+16c8e mainCRTStartup at D:\a\_work\1\s\src\vctools\crt\vcstartup\src\startup\exe_main.cpp:17
0x7ffaf61b7374: KERNEL32.DLL+17374 BaseThreadInitThunk
0x7ffaf6b5cc91: ntdll.dll+4cc91 RtlUserThreadStart

=== Stack Trace (RSP-based) ===
Stack trace (RSP-based):
0x7ffa6f509369: MSVCP140D.dll+0x69369
0x7ff6ba09463b: TestApplication.exe+0x1463b
0x7ff6ba093786: TestApplication.exe+0x13786
0x7ffa6f511978: MSVCP140D.dll+0x71978
0x7ff6ba095c65: TestApplication.exe+0x15c65
0x7ff6ba09168b: TestApplication.exe+0x1168b

```

## 주요 기능

- **Vectored Exception Handler(VEH)** 활용: Windows SEH 메커니즘을 이용해 다양한 종류의 예외를 감지
- **상세 로그 파일 생성**: 다음 정보를 포함하는 로그 파일 자동 생성
  - 예외 코드 및 설명
  - 예외 발생 주소
  - 프로세스 및 스레드 ID
  - CPU 레지스터 상태
  - 스택 트레이스 (두 가지 방식으로 생성)

- **Thread Local Storage(TLS)** 사용: 다중 스레드 환경에서 재진입 방지 구현

- **심볼 정보 활용**: DbgHelp 라이브러리를 통한 함수명, 소스 파일, 라인 번호 정보 수집

## 지원하는 예외 타입

- Access Violation
- Integer Divide-by-Zero
- Stack Overflow
- Illegal Instruction
- 하드웨어, 소프트웨어 브레이크포인트 및 기타 예외 타입은 제외하였습니다.

## 사용 방법

1. `ExceptionReporter.dll`을 **타겟 애플리케이션에 주입**합니다.
2. dllmain에서 예외 핸들러를 자동으로 등록합니다.
3. 예외 발생 시 `C:\ExceptionLogs\` 디렉토리에 로그 파일이 자동 생성됩니다.
   - 파일명 형식: `Exception_{프로세스ID}_{타임스탬프}.log`

## 로그 파일 구성

로그 파일은 다음 섹션으로 구성됩니다:

1. **예외 정보**: 예외 코드, 타입, 주소 등의 기본 정보
2. **레지스터 상태**: CPU 레지스터 값(x86/x64 아키텍처 모두 지원)
3. **스택 트레이스**: DbgHelp를 이용한 스택 트레이스
4. **RSP 기반 스택 트레이스**: DbgHelp 기반으로 콜 스택을 조회할 수 없을 시 하지 않을 시 다른 방법으로 콜 스택 분석 제공

## 테스트 애플리케이션

이 프로젝트는 Exception Reporter의 기능을 테스트하기 위한 TestApplication을 포함합니다.

TestApplication은 다양한 유형의 SEH 예외를 의도적으로 발생시켜 Exception Reporter의 동작을 검증할 수 있게 해줍니다.

### 테스트 애플리케이션 기능

- **메뉴 기반 인터페이스**: 다양한 예외 타입 선택 가능
- **지원하는 테스트 예외 유형**:
  - 접근 위반 (Access Violation)
  - 0으로 나누기 (Divide by Zero)
  - 스택 오버플로우 (Stack Overflow)
  - 잘못된 매개변수 (Invalid Parameter)
  - 잘못된 명령어 (Illegal Instruction)
- **일괄 테스트**: 모든 예외 유형을 연속으로 테스트하는 옵션 제공

### 테스트 애플리케이션 사용법

1. TestApplication을 실행합니다.
2. ExceptionReporter.dll을 TestApplication 프로세스에 주입합니다.
2. 메뉴에서 발생시킬 예외 유형을 선택합니다.
3. ExceptionReporter.dll이 로드되어 있으면 예외 발생 시 로그 파일이 생성됩니다.
4. `C:\ExceptionLogs\` 디렉토리에서 생성된 로그 파일을 확인합니다.

## 개발 및 디버깅 팁

- 제대로 된 스택 트레이스를 얻기 위해서는 PDB 파일(디버그 심볼)이 필요합니다.
- 릴리스 빌드에서도 의미 있는 로그를 생성하려면 심볼 정보를 포함하도록 빌드 설정을 구성하세요.