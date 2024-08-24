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

std::string name = skCrypt("").decrypt();
std::string ownerid = skCrypt("").decrypt();
std::string secret = skCrypt("").decrypt();
std::string version = skCrypt("").decrypt();
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
