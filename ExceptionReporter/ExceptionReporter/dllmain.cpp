// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include <Windows.h>
#include <DbgHelp.h>
#include <time.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <Psapi.h>  // For GetModuleInformation

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")  // For Psapi functions

// 예외 정보를 저장할 디렉토리 경로
const std::wstring LOG_DIRECTORY = L"C:\\ExceptionLogs\\";
PVOID g_ExceptionHandler = nullptr;

// Thread Local Storage 인덱스
DWORD g_TlsIndex = TLS_OUT_OF_INDEXES;

// 스택 트레이스 정보 수집
std::string GetStackTrace(CONTEXT* contextInput, HANDLE hProcess) {
    std::stringstream stackTrace;
    
    __try {
        if (!contextInput || !hProcess) {
            return "Invalid context or process handle";
        }
        
        // 원본 Context를 복사
        CONTEXT contextCopy;
        memcpy(&contextCopy, contextInput, sizeof(CONTEXT));
        CONTEXT* context = &contextCopy;  // 복사본 사용
        
        DWORD machineType;
        
        #ifdef _M_IX86
            machineType = IMAGE_FILE_MACHINE_I386;
        #elif _M_X64
            machineType = IMAGE_FILE_MACHINE_AMD64;
        #endif

        STACKFRAME64 frame = {};
        frame.AddrPC.Mode = AddrModeFlat;
        frame.AddrFrame.Mode = AddrModeFlat;
        frame.AddrStack.Mode = AddrModeFlat;

        #ifdef _M_IX86
            frame.AddrPC.Offset = context->Eip;
            frame.AddrFrame.Offset = context->Ebp;
            frame.AddrStack.Offset = context->Esp;
        #elif _M_X64
            frame.AddrPC.Offset = context->Rip;
            frame.AddrFrame.Offset = context->Rbp;
            frame.AddrStack.Offset = context->Rsp;
        #endif

        if (!SymInitialize(hProcess, NULL, TRUE)) {
            stackTrace << "Failed to initialize symbol handler: " << GetLastError() << "\n";
            return stackTrace.str();
        }
        
        SymSetOptions(SYMOPT_LOAD_LINES);

        // 스택 트레이스 가져오기
        stackTrace << "Stack trace:\n";
        for (int i = 0; i < 50; i++) {
            if (!StackWalk64(machineType, hProcess, GetCurrentThread(), &frame, context, NULL, 
                           SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
                break;
            }

            if (frame.AddrPC.Offset == 0) {
                break;
            }

            __try {
                // 함수명 및 라인 정보 가져오기
                char symbol_buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
                PSYMBOL_INFO symbol = (PSYMBOL_INFO)symbol_buffer;
                symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
                symbol->MaxNameLen = MAX_SYM_NAME;

                DWORD64 displacement = 0;
                IMAGEHLP_LINE64 line;
                DWORD lineDisplacement = 0;
                line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

                stackTrace << std::hex << "0x" << frame.AddrPC.Offset << std::dec << ": ";
                
                // 모듈 정보 가져오기
                DWORD64 moduleBase = SymGetModuleBase64(hProcess, frame.AddrPC.Offset);
                char moduleName[MAX_PATH] = "<unknown module>";
                
                if (moduleBase) {
                    if (GetModuleFileNameA((HMODULE)moduleBase, moduleName, MAX_PATH)) {
                        // 파일 경로에서 파일 이름만 추출
                        char* fileName = strrchr(moduleName, '\\');
                        if (fileName) {
                            // '\'를 건너뛴 위치를 사용
                            fileName++;
                        } else {
                            fileName = moduleName; // '\'가 없는 경우
                        }
                        stackTrace << fileName;
                    } else {
                        stackTrace << "<unknown module>";
                    }
                    
                    // 모듈 내 오프셋 추가
                    stackTrace << "+" << std::hex << (frame.AddrPC.Offset - moduleBase) << std::dec;
                } else {
                    stackTrace << "<unknown module>";
                }
                
                stackTrace << " ";
                
                if (SymFromAddr(hProcess, frame.AddrPC.Offset, &displacement, symbol)) {
                    stackTrace << symbol->Name;
                    if (SymGetLineFromAddr64(hProcess, frame.AddrPC.Offset, &lineDisplacement, &line)) {
                        stackTrace << " at " << line.FileName << ":" << line.LineNumber;
                    }
                } else {
                    stackTrace << "<unknown function>";
                }
                stackTrace << "\n";
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                stackTrace << "<error getting function info>\n";
                continue;
            }
        }

        SymCleanup(hProcess);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        stackTrace << "Exception occurred while generating stack trace\n";
    }
    
    return stackTrace.str();
}

// Get stack trace based on RSP (stack pointer) value without using dbghelp/psapi
std::string GetStackTraceFromRsp(CONTEXT* contextInput, HANDLE hProcess) {
    std::stringstream stackTrace;

    __try {
        if (!contextInput || !hProcess) {
            return "Invalid context or process handle";
        }

        stackTrace << "Stack trace (RSP-based):\n";

        // Get stack pointer
        uintptr_t stackPtr;
#ifdef _M_IX86
        stackPtr = contextInput->Esp;
#elif _M_X64
        stackPtr = contextInput->Rsp;
#endif

        // Track already seen addresses to avoid infinite loops
        std::vector<uintptr_t> seenAddresses;
        const int MAX_FRAMES = 100;  // Maximum stack depth to avoid infinite loops
        int validFrames = 0;

        for (int i = 0; i < MAX_FRAMES && validFrames < 50; i++) {
            // Check for invalid pointer
            if (!stackPtr || (stackPtr & (sizeof(uintptr_t) - 1)) != 0) {
                break;  // Misaligned stack pointer
            }

            // Read potential return address from stack
            uintptr_t retAddr = 0;
            SIZE_T bytesRead;
            if (!ReadProcessMemory(hProcess, (LPCVOID)stackPtr, &retAddr, sizeof(retAddr), &bytesRead) ||
                bytesRead != sizeof(retAddr)) {
                // Move to next stack entry and continue
                stackPtr += sizeof(uintptr_t);
                continue;
            }

            stackPtr += sizeof(uintptr_t);  // Move to next stack entry

            // Skip null addresses
            if (retAddr == 0) {
                continue;
            }

            // Check if we've seen this address before (loop detection)
            if (std::find(seenAddresses.begin(), seenAddresses.end(), retAddr) != seenAddresses.end()) {
                continue;
            }

            // Check if the address is in executable memory using VirtualQueryEx
            MEMORY_BASIC_INFORMATION memInfo;
            if (VirtualQueryEx(hProcess, (LPCVOID)retAddr, &memInfo, sizeof(memInfo)) == 0) {
                continue; // Cannot query memory information
            }

            // Check for any execute permissions in the memory region
            DWORD execProtection = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

            if ((memInfo.Protect & execProtection) == 0) {
                continue; // Not executable memory
            }

            // At this point, the address is executable, so include it
            seenAddresses.push_back(retAddr);
            validFrames++;

            // Get module name without using psapi
            char moduleName[MAX_PATH] = "<unknown>";
            HMODULE hMod = (HMODULE)memInfo.AllocationBase;
            if (hMod != NULL && GetModuleFileNameA(hMod, moduleName, MAX_PATH) > 0) {
                // Extract just the filename
                char* fileName = strrchr(moduleName, '\\');
                if (fileName) {
                    fileName++;
                }
                else {
                    fileName = moduleName;
                }

                // Calculate offset from module base
                uintptr_t moduleBase = (uintptr_t)memInfo.AllocationBase;
                stackTrace << std::hex << "0x" << retAddr << std::dec << ": " << fileName
                    << "+0x" << std::hex << (retAddr - moduleBase) << std::dec;
            }
            else {
                // Just show the address and memory region information
                stackTrace << std::hex << "0x" << retAddr << std::dec
                    << ": <executable memory at 0x" << std::hex << (uintptr_t)memInfo.BaseAddress
                    << " size: 0x" << memInfo.RegionSize << ">";
            }

            stackTrace << "\n";
        }

        if (validFrames == 0) {
            stackTrace << "No executable addresses found in stack\n";
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        stackTrace << "Exception occurred while generating RSP-based stack trace\n";
    }

    return stackTrace.str();
}



// 타임스탬프 생성
std::wstring GetTimeStampStr() {
    __try {
        time_t now = time(0);
        struct tm timeinfo;
        if (localtime_s(&timeinfo, &now) != 0) {
            return L"UnknownTime";
        }
        
        std::wstringstream ss;
        ss << std::put_time(&timeinfo, L"%Y%m%d_%H%M%S");
        return ss.str();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return L"ExceptionTime";
    }
}

// 예외 정보를 파일로 저장
void WriteExceptionToFile(EXCEPTION_POINTERS* pExceptionInfo) {
    __try {
        // 디렉토리 생성
        if (!CreateDirectoryW(LOG_DIRECTORY.c_str(), NULL) && 
            GetLastError() != ERROR_ALREADY_EXISTS) {
            return; // 디렉토리 생성 실패
        }

        // 파일명 생성 (프로세스 ID와 타임스탬프 포함)
        std::wstring filename;
        __try {
            filename = LOG_DIRECTORY + L"Exception_" + 
                      std::to_wstring(GetCurrentProcessId()) + L"_" + 
                      GetTimeStampStr() + L".log";
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            // 파일명 생성 중 예외 발생하면 기본 이름 사용
            filename = LOG_DIRECTORY + L"Exception_Unknown.log";
        }
        
        // 파일 오픈
        std::ofstream logFile;
        __try {
            logFile.open(filename);
            if (!logFile.is_open()) {
                return;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            return; // 파일 열기 실패
        }

        // 예외 기본 정보 기록
        __try {
            EXCEPTION_RECORD* record = pExceptionInfo->ExceptionRecord;
            DWORD exceptionCode = record ? record->ExceptionCode : 0;
            
            logFile << "=== Exception Report ===" << std::endl;
            logFile << "Process ID: " << GetCurrentProcessId() << std::endl;
            logFile << "Thread ID: " << GetCurrentThreadId() << std::endl;
            
            if (record) {
                logFile << "Exception Code: 0x" << std::hex << exceptionCode << std::dec << " (";
                
                // 일반적인 예외 코드에 대한 설명 추가
                switch (exceptionCode) {
                    case EXCEPTION_ACCESS_VIOLATION:
                        logFile << "EXCEPTION_ACCESS_VIOLATION";
                        if (record->NumberParameters >= 2) {
                            logFile << " - " << (record->ExceptionInformation[0] ? "Writing" : "Reading") 
                                    << " at address 0x" << std::hex << record->ExceptionInformation[1];
                        }
                        break;
                    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: logFile << "EXCEPTION_ARRAY_BOUNDS_EXCEEDED"; break;
                    case EXCEPTION_BREAKPOINT: logFile << "EXCEPTION_BREAKPOINT"; break;
                    case EXCEPTION_DATATYPE_MISALIGNMENT: logFile << "EXCEPTION_DATATYPE_MISALIGNMENT"; break;
                    case EXCEPTION_FLT_DENORMAL_OPERAND: logFile << "EXCEPTION_FLT_DENORMAL_OPERAND"; break;
                    case EXCEPTION_FLT_DIVIDE_BY_ZERO: logFile << "EXCEPTION_FLT_DIVIDE_BY_ZERO"; break;
                    case EXCEPTION_FLT_INEXACT_RESULT: logFile << "EXCEPTION_FLT_INEXACT_RESULT"; break;
                    case EXCEPTION_FLT_INVALID_OPERATION: logFile << "EXCEPTION_FLT_INVALID_OPERATION"; break;
                    case EXCEPTION_FLT_OVERFLOW: logFile << "EXCEPTION_FLT_OVERFLOW"; break;
                    case EXCEPTION_FLT_STACK_CHECK: logFile << "EXCEPTION_FLT_STACK_CHECK"; break;
                    case EXCEPTION_FLT_UNDERFLOW: logFile << "EXCEPTION_FLT_UNDERFLOW"; break;
                    case EXCEPTION_ILLEGAL_INSTRUCTION: logFile << "EXCEPTION_ILLEGAL_INSTRUCTION"; break;
                    case EXCEPTION_IN_PAGE_ERROR: logFile << "EXCEPTION_IN_PAGE_ERROR"; break;
                    case EXCEPTION_INT_DIVIDE_BY_ZERO: logFile << "EXCEPTION_INT_DIVIDE_BY_ZERO"; break;
                    case EXCEPTION_INT_OVERFLOW: logFile << "EXCEPTION_INT_OVERFLOW"; break;
                    case EXCEPTION_INVALID_DISPOSITION: logFile << "EXCEPTION_INVALID_DISPOSITION"; break;
                    case EXCEPTION_NONCONTINUABLE_EXCEPTION: logFile << "EXCEPTION_NONCONTINUABLE_EXCEPTION"; break;
                    case EXCEPTION_PRIV_INSTRUCTION: logFile << "EXCEPTION_PRIV_INSTRUCTION"; break;
                    case EXCEPTION_SINGLE_STEP: logFile << "EXCEPTION_SINGLE_STEP"; break;
                    case EXCEPTION_STACK_OVERFLOW: logFile << "EXCEPTION_STACK_OVERFLOW"; break;
                    default: logFile << "UNKNOWN_EXCEPTION"; break;
                }
                logFile << ")" << std::endl;
                
                logFile << "Exception Address: 0x" << std::hex << record->ExceptionAddress << std::dec << std::endl;
            } else {
                logFile << "Exception Record unavailable" << std::endl;
            }
            logFile << std::endl;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            logFile << "Error while writing exception information" << std::endl;
        }

        // 레지스터 정보 출력
        __try {
            CONTEXT* ctx = pExceptionInfo->ContextRecord;
            if (ctx) {
                logFile << "=== Register State ===" << std::endl;
                
                #ifdef _M_IX86
                    logFile << "EAX: 0x" << std::hex << ctx->Eax << std::endl;
                    logFile << "EBX: 0x" << ctx->Ebx << std::endl;
                    logFile << "ECX: 0x" << ctx->Ecx << std::endl;
                    logFile << "EDX: 0x" << ctx->Edx << std::endl;
                    logFile << "ESI: 0x" << ctx->Esi << std::endl;
                    logFile << "EDI: 0x" << ctx->Edi << std::endl;
                    logFile << "EIP: 0x" << ctx->Eip << std::endl;
                    logFile << "ESP: 0x" << ctx->Esp << std::endl;
                    logFile << "EBP: 0x" << ctx->Ebp << std::endl;
                #elif _M_X64
                    logFile << "RAX: 0x" << std::hex << ctx->Rax << std::endl;
                    logFile << "RBX: 0x" << ctx->Rbx << std::endl;
                    logFile << "RCX: 0x" << ctx->Rcx << std::endl;
                    logFile << "RDX: 0x" << ctx->Rdx << std::endl;
                    logFile << "RSI: 0x" << ctx->Rsi << std::endl;
                    logFile << "RDI: 0x" << ctx->Rdi << std::endl;
                    logFile << "R8:  0x" << ctx->R8 << std::endl;
                    logFile << "R9:  0x" << ctx->R9 << std::endl;
                    logFile << "R10: 0x" << ctx->R10 << std::endl;
                    logFile << "R11: 0x" << ctx->R11 << std::endl;
                    logFile << "R12: 0x" << ctx->R12 << std::endl;
                    logFile << "R13: 0x" << ctx->R13 << std::endl;
                    logFile << "R14: 0x" << ctx->R14 << std::endl;
                    logFile << "R15: 0x" << ctx->R15 << std::endl;
                    logFile << "RIP: 0x" << ctx->Rip << std::endl;
                    logFile << "RSP: 0x" << ctx->Rsp << std::endl;
                    logFile << "RBP: 0x" << ctx->Rbp << std::endl;
                #endif
                logFile << std::endl;
            } else {
                logFile << "Context Record unavailable" << std::endl;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            logFile << "Error while writing register information" << std::endl;
        }

        // 스택 트레이스 출력
        __try {
            if (pExceptionInfo->ContextRecord) {
                logFile << "=== Stack Trace ===" << std::endl;
                logFile << GetStackTrace(pExceptionInfo->ContextRecord, GetCurrentProcess()) << std::endl;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            logFile << "Error while generating stack trace" << std::endl;
        }

        // RSP 기반 스택 트레이스 출력 추가
        __try {
            if (pExceptionInfo->ContextRecord) {
                logFile << "=== Stack Trace (RSP-based) ===" << std::endl;
                logFile << GetStackTraceFromRsp(pExceptionInfo->ContextRecord, GetCurrentProcess()) << std::endl;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            logFile << "Error while generating RSP-based stack trace" << std::endl;
        }

        // 파일 닫기
        logFile.close();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // 최상위 예외 처리 - 아무 것도 하지 않음
    }
}

// Vectored Exception Handler 콜백 함수
LONG CALLBACK VectoredExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo) {
    // 특정 예외만 처리, 나머지는 모두 무시
    DWORD exceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;
    
    // 처리할 예외인지 확인
    bool shouldProcess = false;
    switch (exceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        case EXCEPTION_DATATYPE_MISALIGNMENT:
        case EXCEPTION_FLT_DENORMAL_OPERAND:
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        case EXCEPTION_FLT_INEXACT_RESULT:
        case EXCEPTION_FLT_INVALID_OPERATION:
        case EXCEPTION_FLT_OVERFLOW:
        case EXCEPTION_FLT_STACK_CHECK:
        case EXCEPTION_FLT_UNDERFLOW:
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_IN_PAGE_ERROR:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_INT_OVERFLOW:
        case EXCEPTION_INVALID_DISPOSITION:
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        case EXCEPTION_PRIV_INSTRUCTION:
        case EXCEPTION_STACK_OVERFLOW:
            shouldProcess = true;
            break;
            
        // EXCEPTION_BREAKPOINT와 EXCEPTION_SINGLE_STEP는 목록에 있지만 디버깅 관련이므로 처리하지 않음
        case EXCEPTION_BREAKPOINT:
        case EXCEPTION_SINGLE_STEP:
        default:
            return EXCEPTION_CONTINUE_SEARCH;
    }
    
    // 목록에 없는 예외라면 무시
    if (!shouldProcess) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // TLS를 사용하여 현재 스레드에서 예외 처리 중인지 확인
    BOOL* pIsHandlingException = (BOOL*)TlsGetValue(g_TlsIndex);
    if (pIsHandlingException == nullptr) {
        // 처음 호출된 경우 TLS 메모리 할당
        pIsHandlingException = (BOOL*)LocalAlloc(LPTR, sizeof(BOOL));
        if (pIsHandlingException == nullptr) {
            // 메모리 할당 실패 시 예외 처리 건너뛰기
            return EXCEPTION_CONTINUE_SEARCH;
        }
        *pIsHandlingException = FALSE;
        TlsSetValue(g_TlsIndex, pIsHandlingException);
    }

    // 재진입 방지 - 동일 스레드에서 이미 예외 처리 중인 경우
    if (*pIsHandlingException) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    // 예외 처리 중임을 표시
    *pIsHandlingException = TRUE;
    
    __try {
        // 예외 정보를 파일에 기록
        WriteExceptionToFile(pExceptionInfo);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // 예외 처리 중 발생한 또 다른 예외는 무시
        // 중첩 예외 발생 시 로깅 시도를 중단하고 계속 진행
    }
    
    // 예외 처리 완료
    *pIsHandlingException = FALSE;
    
    // 다음 예외 핸들러로 진행
    return EXCEPTION_CONTINUE_SEARCH;
}

// 스레드 종료시 TLS 리소스 해제를 위한 함수
void CleanupTlsData() {
    BOOL* pIsHandlingException = (BOOL*)TlsGetValue(g_TlsIndex);
    if (pIsHandlingException != nullptr) {
        LocalFree(pIsHandlingException);
        TlsSetValue(g_TlsIndex, nullptr);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // TLS 인덱스 할당
        g_TlsIndex = TlsAlloc();
        if (g_TlsIndex == TLS_OUT_OF_INDEXES) {
            // TLS 할당 실패
            return FALSE;
        }
        
        // 벡터화된 예외 핸들러 등록
        g_ExceptionHandler = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        // 스레드 종료 시 TLS 데이터 정리
        CleanupTlsData();
        break;

    case DLL_PROCESS_DETACH:
        // 핸들러 제거
        if (g_ExceptionHandler) {
            RemoveVectoredExceptionHandler(g_ExceptionHandler);
            g_ExceptionHandler = nullptr;
        }
        
        // TLS 데이터 정리 및 인덱스 해제
        CleanupTlsData();
        if (g_TlsIndex != TLS_OUT_OF_INDEXES) {
            TlsFree(g_TlsIndex);
            g_TlsIndex = TLS_OUT_OF_INDEXES;
        }
        break;
    }
    return TRUE;
}