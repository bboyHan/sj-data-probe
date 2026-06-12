// DataProbe ProcessHook DLL
// Injected into target process, hooks SSL_write/SSL_read via MinHook.
// Communicates with DataProbe Engine via Named Pipe.
//
// Build (with MinGW):
//   x86_64-w64-mingw32-g++ -shared -o hook.dll hook.cpp -lws2_32 -static -O2

#include <windows.h>
#include <cstdio>

// ── MinHook (lightweight inline hooking) ──
// In production, include MinHook.h and link minhook.a
// Simplified for demonstration: use a trampoline pattern

typedef int (WINAPI *SSL_write_t)(void* ssl, const void* buf, int num);
typedef int (WINAPI *SSL_read_t)(void* ssl, void* buf, int num);

static SSL_write_t Real_SSL_write = nullptr;
static SSL_read_t Real_SSL_read = nullptr;

// ── Named Pipe IPC ──
static HANDLE g_pipe = INVALID_HANDLE_VALUE;

bool ConnectToDataProbe() {
    for (int i = 0; i < 30; i++) {
        g_pipe = CreateFileA(
            "\\.\pipe\DataProbeHookPipe",
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_pipe != INVALID_HANDLE_VALUE) return true;
        Sleep(100);
    }
    return false;
}

void SendToEngine(const char* data, int len) {
    if (g_pipe == INVALID_HANDLE_VALUE) return;
    DWORD written;
    DWORD prefix = (DWORD)len;
    WriteFile(g_pipe, &prefix, 4, &written, nullptr);
    WriteFile(g_pipe, data, len, &written, nullptr);
}

// ── Hooked Functions ──

int WINAPI Hooked_SSL_write(void* ssl, const void* buf, int num) {
    if (num > 0 && buf) {
        SendToEngine((const char*)buf, num);
    }
    return Real_SSL_write(ssl, buf, num);
}

int WINAPI Hooked_SSL_read(void* ssl, void* buf, int num) {
    int result = Real_SSL_read(ssl, buf, num);
    if (result > 0 && buf) {
        SendToEngine((const char*)buf, result);
    }
    return result;
}

// ── Entry Point ──

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // Connect to engine
        ConnectToDataProbe();

        // In production: use MinHook to install hooks
        // MH_Initialize();
        // MH_CreateHook(&SSL_write, &Hooked_SSL_write, (void**)&Real_SSL_write);
        // MH_EnableHook(&SSL_write);

        // Log startup
        const char* msg = "[DataProbe Hook] Loaded";
        SendToEngine(msg, lstrlenA(msg));
    }
    return TRUE;
}
