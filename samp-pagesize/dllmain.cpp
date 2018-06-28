#include "dllmain.h"

static void Thread()
{
	Pattern pattern(GetCurrentProcess(), GetModuleHandleA("samp.dll"));

	DWORD offsets[3] = { NULL }, OldProtect = NULL;

	static const char pagesize_string[] = "pagesize [1-20] (lines)";

	offsets[0] = pattern.FindPattern("\x89\x44\x24\x04\x74\x3F\x56\xE8\x00\x00\x00\x00\x8B\xF0\x83\xC4\x04\x83\xFE\x0A\x7C\x2F\x83\xFE\x14\x7F\x2A\x8B\x0D\x00\x00\x00\x00\x85\xC9", "xxxxxxxx????xxxxxxxxxxxxxxxxx????xx") + 0x13; 
	offsets[1] = pattern.FindPattern("\x8B\x44\x24\x04\x83\xF8\x0A\x56\x8B\xF1\x7C\x16\x83\xF8\x64\x7F\x11\x89\x06\xE8\x00\x00\x00\x00\xC7\x86\x00\x00\x00\x00\x00\x00\x00\x00\x5E", "xxxxxxxxxxxxxxxxxxxx????xx????????x") + 0x6;
	offsets[2] = pattern.FindPattern("\x5E\x59\xC3\xA1\x00\x00\x00\x00\x85\xC0\x74\x0E\x68\x00\x00\x00\x00\x50\xE8\x00\x00\x00\x00\x83\xC4\x08", "xxxx????xxxxx????xx????xxx") + 0xD;

	VirtualProtect((void*)offsets[0], 1, PAGE_EXECUTE_READWRITE, &OldProtect);
	VirtualProtect((void*)offsets[1], 1, PAGE_EXECUTE_READWRITE, &OldProtect);
	VirtualProtect((void*)offsets[2], 4, PAGE_EXECUTE_READWRITE, &OldProtect);

	*(BYTE*)offsets[0] = 0x1;
	*(BYTE*)offsets[1] = 0x1;
	*(DWORD*)offsets[2] = (DWORD)&pagesize_string;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Thread, 0, 0, 0);
	}
	return TRUE;
}

