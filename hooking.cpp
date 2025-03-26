#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <chrono>
#include <thread>


class SafeHook {
    HHOOK m_hook;
public:
    SafeHook(HHOOK hook = nullptr) : m_hook(hook) {}
    ~SafeHook() { if (m_hook) UnhookWindowsHookEx(m_hook); }
    operator HHOOK() const { return m_hook; }
    HHOOK* operator&() { return &m_hook; }
    HHOOK release() {
        HHOOK hook = m_hook;
        m_hook = nullptr;
        return hook;
    }
};


class SafeModule {
    HMODULE m_module;
public:
    SafeModule(HMODULE module = nullptr) : m_module(module) {}
    ~SafeModule() { if (m_module) FreeLibrary(m_module); }
    operator HMODULE() const { return m_module; }
    HMODULE* operator&() { return &m_module; }
    HMODULE release() {
        HMODULE module = m_module;
        m_module = nullptr;
        return module;
    }
};

void DisplayThreadInfo(DWORD processId) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "unable to createthreadsnapshot (error: " << GetLastError() << ")" << std::endl;
        return;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    std::cout << "\n=== rbx thread informations: " << processId << " ===" << std::endl;

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                std::cout << "thread ID: " << te32.th32ThreadID
                    << " | base priority: " << te32.tpBasePri
                    << std::endl;
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);
    std::cout << "=================================\n" << std::endl;
}

bool SetRobloxHook(DWORD threadId) {
    
    SafeModule hDll(LoadLibraryExA("nvoglv64.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES));
    if (!hDll) {
        std::cerr << "failed to load nvoglv64.dll (error: " << GetLastError() << ")" << std::endl;
        return false;
    }

    std::cout << "nvoglv64.dll loaded sucessfuly at: 0x" << std::hex << (HMODULE)hDll << std::dec << std::endl;

    
    HOOKPROC NextHook = (HOOKPROC)GetProcAddress(hDll, "NextHook");
    if (!NextHook) {
        std::cerr << "Failed to locate NextHook function (Error: " << GetLastError() << ")" << std::endl;
        return false;
    }

    std::cout << "NextHook function at: 0x" << std::hex << NextHook << std::dec << std::endl;

    
    SafeHook hHook(SetWindowsHookEx(WH_GETMESSAGE, NextHook, hDll, threadId));
    if (!hHook) {
        std::cerr << "Failed to set hook (Error: " << GetLastError() << ")" << std::endl;
        return false;
    }

    std::cout << "Hook successfully installed (Handle: 0x" << std::hex << (HHOOK)hHook << ")" << std::dec << std::endl;

   
    for (int i = 0; i < 3; i++) {
        if (!PostThreadMessage(threadId, WM_NULL, 0, 0)) {
            std::cerr << "Failed to post thread message (Error: " << GetLastError() << ")" << std::endl;
        }
        else {
            std::cout << "Trigger message " << (i + 1) << "/3 sent to thread " << threadId << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }


    hDll.release(); 
    hHook.release(); 

    return true;
}

int main() {
    std::cout << "haker Injector" << std::endl;
    std::cout << "==========================" << std::endl;

    
    HWND RobloxWindow = nullptr;
    for (int i = 0; i < 10 && !RobloxWindow; i++) {
        RobloxWindow = FindWindowA(nullptr, "Roblox");
        if (!RobloxWindow) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    if (!RobloxWindow) {
        std::cerr << "Roblox window not found" << std::endl;
        return 1;
    }

    
    DWORD RobloxPID = 0;
    DWORD RobloxThreadTID = GetWindowThreadProcessId(RobloxWindow, &RobloxPID);

    std::cout << "Roblox Process Information:" << std::endl;
    std::cout << "  Window Handle: 0x" << std::hex << RobloxWindow << std::dec << std::endl;
    std::cout << "  Process ID: " << RobloxPID << std::endl;
    std::cout << "  Main Thread ID: " << RobloxThreadTID << std::endl;

    DisplayThreadInfo(RobloxPID);

    
    if (!SetRobloxHook(RobloxThreadTID)) {
        return 1;
    }

    std::cout << "\nHook installed successfully. Roblox should remain stable." << std::endl;
    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get();

    return 0;
}
