// TestApplication.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <iostream>
#include <Windows.h>
#include <excpt.h>
#include <string>

// SEH 예외를 발생시키는 함수들
void TriggerAccessViolation() {
    std::cout << "접근 위반(Access Violation) 예외 발생시키는 중...\n";
    int* p = nullptr;
    *p = 10; // 널 포인터 역참조 - 접근 위반
}

void TriggerDivideByZero() {
    std::cout << "0으로 나누기 예외 발생시키는 중...\n";
    int a = 5;
    int b = 0;
    int c = a / b; // 0으로 나누기
    std::cout << "결과: " << c << std::endl; // 실행되지 않음
}

void TriggerStackOverflow() {
    std::cout << "스택 오버플로우 예외 발생시키는 중...\n";
    
    // 무한 재귀 호출로 스택 오버플로우 발생
    static void (*recursiveFunc)() = []() {
        char buffer[1024]; // 스택에 메모리 할당
        recursiveFunc(); // 무한 재귀 호출
    };
    
    recursiveFunc();
}

void TriggerInvalidParameter() {
    std::cout << "잘못된 매개변수 예외 발생시키는 중...\n";
    char buffer[10];
    strcpy_s(buffer, 1, "이 문자열은 버퍼보다 깁니다"); // 잘못된 매개변수
}

void TriggerIllegalInstruction() {
    std::cout << "잘못된 명령어 예외 발생시키는 중...\n";
    
    // 잘못된 명령어 실행을 위한 함수 포인터 트릭
    void (*invalidFunc)() = (void(*)())0xFFFFFFFF;
    invalidFunc(); // 잘못된 함수 포인터 호출
}

// SEH 예외를 테스트하는 함수
int ExecuteSEHTest(void (*testFunction)(), const std::string& exceptionName) {
    __try {
        testFunction();
        return 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DWORD exceptionCode = GetExceptionCode();
        std::cout << exceptionName << " 예외가 발생했습니다. 예외 코드: 0x" 
                  << std::hex << exceptionCode << std::dec << std::endl;
        return exceptionCode;
    }
}

void DisplayMenu() {
    std::cout << "\n=== Windows SEH 예외 테스트 프로그램 ===\n";
    std::cout << "1. 접근 위반 (Access Violation)\n";
    std::cout << "2. 0으로 나누기 (Divide by Zero)\n";
    std::cout << "3. 스택 오버플로우 (Stack Overflow)\n";
    std::cout << "4. 잘못된 매개변수 (Invalid Parameter)\n";
    std::cout << "5. 잘못된 명령어 (Illegal Instruction)\n";
    std::cout << "6. 모든 SEH 예외 테스트\n";
    std::cout << "0. 종료\n";
    std::cout << "선택: ";
}

int main()
{
    int choice = -1;
    
    while (choice != 0) {
        DisplayMenu();
        std::cin >> choice;
        
        switch (choice) {
            case 0:
                std::cout << "프로그램을 종료합니다.\n";
                break;
            case 1:
                ExecuteSEHTest(TriggerAccessViolation, "접근 위반");
                break;
            case 2:
                ExecuteSEHTest(TriggerDivideByZero, "0으로 나누기");
                break;
            case 3:
                ExecuteSEHTest(TriggerStackOverflow, "스택 오버플로우");
                break;
            case 4:
                ExecuteSEHTest(TriggerInvalidParameter, "잘못된 매개변수");
                break;
            case 5:
                ExecuteSEHTest(TriggerIllegalInstruction, "잘못된 명령어");
                break;
            case 6:
                std::cout << "\n모든 SEH 예외 테스트를 시작합니다...\n";
                ExecuteSEHTest(TriggerAccessViolation, "접근 위반");
                std::cout << "계속하려면 아무 키나 누르세요...\n";
                std::cin.ignore(); std::cin.get();
                
                ExecuteSEHTest(TriggerDivideByZero, "0으로 나누기");
                std::cout << "계속하려면 아무 키나 누르세요...\n";
                std::cin.ignore(); std::cin.get();
                
                ExecuteSEHTest(TriggerInvalidParameter, "잘못된 매개변수");
                std::cout << "계속하려면 아무 키나 누르세요...\n";
                std::cin.ignore(); std::cin.get();
                
                ExecuteSEHTest(TriggerIllegalInstruction, "잘못된 명령어");
                std::cout << "계속하려면 아무 키나 누르세요...\n";
                std::cin.ignore(); std::cin.get();
                
                // 스택 오버플로우는 마지막에 테스트 (복구가 어려울 수 있음)
                ExecuteSEHTest(TriggerStackOverflow, "스택 오버플로우");
                break;
            default:
                std::cout << "잘못된 선택입니다. 다시 선택해주세요.\n";
        }
        
        if (choice != 0) {
            std::cout << "\n계속하려면 아무 키나 누르세요...";
            std::cin.ignore();
            std::cin.get();
            system("cls"); // 화면 지우기
        }
    }
    
    return 0;
}

// 프로그램 실행: <Ctrl+F5> 또는 [디버그] > [디버깅하지 않고 시작] 메뉴
// 프로그램 디버그: <F5> 키 또는 [디버그] > [디버깅 시작] 메뉴
