// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vector>
#include "toml.hpp"
#include "SigScan.h"

toml::table cfg_file;
bool cfg_overwrite = false;

bool console = false;

void InjectCode(void* address, const std::vector<uint8_t> data)
{
    const size_t byteCount = data.size() * sizeof(uint8_t);

    DWORD oldProtect;
    VirtualProtect(address, byteCount, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(address, data.data(), byteCount);
    VirtualProtect(address, byteCount, oldProtect, nullptr);
}

uint8_t byteAt(uint64_t num, unsigned char pos)
{
    return (num >> (8 * pos)) & 0xff;
}

__int64 __fastcall hook_overwsave(__int64 a1)
{
    return *(unsigned __int8*)(a1 + 0x11D) = 1;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // console = freopen("CONOUT$", "w", stdout) != NULL;

        // if(console) printf("[Stewie300] Initializing...\n");

        // try
        // {
        //     cfg_file = toml::parse_file("config.toml");
        //     try
        //     {
        //         cfg_overwrite = cfg_file["permanent"].value_or(false);
        //     }
        //     catch (std::exception& exception)
        //     {
        //         if (console) printf("Failed to read config values. %s\n", exception.what());
        //     }
        // }
        // catch (std::exception& exception)
        // {
        //     if (console) printf("Failed to parse config.toml: %s\n", exception.what());
        // }
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void PreInit() // Apply any patches here
{
    console = freopen("CONOUT$", "w", stdout) != NULL;

    if (console) printf("[StrArray] Applying patches...\n");

    const char signature[] = "\x48\x85\xF6\x74\x4E\x4D\x8B\x87\x00\x00\x00\x00\x49\x69\xC6\x00\x00\x00\x00\x42\x8B\x0C\x00\x81\xC1\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x49\x63\xCC\x48\x69\xD1\x00\x00\x00\x00\x49\x8D\x48\x08\x48\x03\xCA\x49\xC7\xC0\x00\x00\x00\x00\x0F\x1F\x80\x00\x00\x00\x00" "\x8D\x8B\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x49\xC7\xC0\x00\x00\x00\x00\x49\xFF\xC0\x42\x80\x3C\x00\x00\x75\xF6\x48\x8B\xD0\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00" "\x48\x85\xF6\x74\x41\x4D\x8B\x85\x00\x00\x00\x00\x49\x6B\xC6\x68\x42\x8B\x0C\x00\x81\xC1\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x49\x63\xCF\x48\x6B\xD1\x68\x49\x8D\x48\x08\x48\x03\xCA\x49\xC7\xC0\x00\x00\x00\x00" "\x48\x85\xF6\x74\x41\x4D\x8B\x85\x00\x00\x00\x00\x49\x6B\xC6\x68\x42\x8B\x0C\x00\x81\xC1\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x49\x63\xCF\x48\x6B\xD1\x68\x49\x8D\x48\x08\x48\x03\xCA\x49\xC7\xC0\x00\x00\x00\x00" "\x48\x85\xF6\x74\x43\x4D\x8B\x85\x00\x00\x00\x00\x43\x8B\x0C\x38\x81\xC1\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x49\x63\xCE\x48\x8D\x0C\xC9\x48\x8D\x49\x01\x49\x8D\x0C\xC8\x49\xC7\xC0\x00\x00\x00\x00\x0F\x1F\x44\x00\x00" "\x48\x85\xF6\x74\x43\x4D\x8B\x85\x00\x00\x00\x00\x43\x8B\x0C\x38\x81\xC1\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x49\x63\xCE\x48\x8D\x0C\xC9\x48\x8D\x49\x01\x49\x8D\x0C\xC8\x49\xC7\xC0\x00\x00\x00\x00\x0F\x1F\x44\x00\x00" "\x41\x8D\x8E\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x49\xC7\xC0\x00\x00\x00\x00\x49\xFF\xC0\x42\x80\x3C\x00\x00\x75\xF6\x48\x8B\xD0\x48\x8D\x4D\xC8\xE8\x00\x00\x00\x00" "\x48\x8B\x15\x00\x00\x00\x00\x48\x85\xD2\x74\x10\x81\xF9\x00\x00\x00\x00\x7D\x08\x48\x63\xC1\x48\x8B\x04\xC2\xC3";
    const char mask[] = "xxxxxxxx????xxx????xxxxxx????x????xxxxxx????xxxxxxxxxx????xxx????" "xx????x????xxx????xxxxxxx?xxxxxxxxx????x????" "xxxxxxxx????xxxxxxxxxx????x????xxxxxxxxxxxxxxxxx????" "xxxxxxxx????xxxxxxxxxx????x????xxxxxxxxxxxxxxxxx????" "xxxxxxxx????xxxxxx????x????xxxxxxxxxxxxxxxxxx????xxxx?" "xxxxxxxx????xxxxxx????x????xxxxxxxxxxxxxxxxxx????xxxx?" "xxx????x????xxx????xxxxxxx?xxxxxxxxxx????" "xxx????xxxxxxx????xxxxxxxxxx";
}

extern "C" __declspec(dllexport) void Init() // Install any hooks here
{
    InjectCode((void*)0x1403F8358, { 0x13, 0x01 }); //chainslide name start for str_array
    InjectCode((void*)0x1403FB100, { 0x4C, 0x09 }); //customize item name start for str_array
    InjectCode((void*)0x1403FD332, { 0x52, 0x01 }); //mix button name start for str_array (incase it crashes)
    InjectCode((void*)0x1403FE382, { 0x58, 0x01 }); //mix slide name start for str_array (incase it crashes)
    InjectCode((void*)0x14040E27C, { 0x47, 0x01 }); //slidertouch name start for str_array
    InjectCode((void*)0x14040F0EC, { 0x2D, 0x01 }); //slide name start for str_array
    InjectCode((void*)0x1403FFBB1, { 0x5E, 0x01 }); //module name start for str_array
    InjectCode((void*)0x14F7C37AE, { 0xFD, 0x0D }); //total str_array entries
}
