/* Standard DLL: DllMain + rundll32 StartW export (PA1005-style). */
#include <windows.h>
#include "beacon_core.h"

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return TRUE;
}

__declspec(dllexport) void CALLBACK StartW(
    HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd;
    (void)hinst;
    (void)lpszCmdLine;
    (void)nCmdShow;
    tempest_beacon_run();
}
