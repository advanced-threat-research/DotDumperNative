#include "pch.h"
#include <string>
#include <windows.h>
#include <iostream>

HANDLE hFile;

void __stdcall PipeSleep() {
	Sleep(100);
}

void __stdcall CheckPipe() {
	if (hFile == nullptr) {
		hFile = CreateFileW(TEXT("\\\\.\\pipe\\dotdumper"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	}
}

extern "C" __declspec(dllexport) BOOL WriteProcessMemoryHook(
	HANDLE   hProcess,
	LPVOID   lpBaseAddress,
	LPCVOID  lpBuffer,
	SIZE_T   nSize,
	SIZE_T * lpNumberOfBytesWritten
)
{
	CheckPipe();

	/*const char* unhook = "unhook-WriteProcessMemoryHook";
	bool output = WriteFile(hFile, unhook, strlen(unhook), nullptr, NULL);
	PipeSleep();

	BOOL result = WriteProcessMemory(hProcess, lpBaseAddress, lpBaseAddress, nSize, lpNumberOfBytesWritten);
	PipeSleep();

	const char* hook = "hook-WriteProcessMemoryHook";
	output = WriteFile(hFile, hook, strlen(hook), nullptr, NULL);
	PipeSleep();*/

	const char* log = "log-WriteProcessMemory";
	bool output = WriteFile(hFile, log, strlen(log), nullptr, NULL);
	PipeSleep();

	DWORD processId = GetProcessId(hProcess);
	std::string data = std::to_string(processId);
	output = WriteFile(hFile, data.c_str(), data.size(), nullptr, NULL);
	PipeSleep();

	output = WriteFile(hFile, &lpBaseAddress, 8, nullptr, NULL);
	PipeSleep();

	output = WriteFile(hFile, lpBuffer, nSize, nullptr, NULL);
	PipeSleep();

	return true;
}

extern "C" __declspec(dllexport) BOOL CreateProcessAHook(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	CheckPipe();

	const char* unhook = "unhook-CreateProcessAHook";
	BOOL output = WriteFile(hFile, unhook, strlen(unhook), nullptr, NULL);
	PipeSleep();

	BOOL result = CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	PipeSleep();

	const char* hook = "hook-CreateProcessAHook";
	output = WriteFile(hFile, hook, strlen(hook), nullptr, NULL);
	PipeSleep();

	const char* log = "log-CreateProcessA";
	output = WriteFile(hFile, log, strlen(log), nullptr, NULL);
	PipeSleep();

	output = WriteFile(hFile, lpApplicationName, strlen(lpApplicationName), nullptr, NULL);
	PipeSleep();

	output = WriteFile(hFile, lpCommandLine, strlen(lpCommandLine), nullptr, NULL);
	PipeSleep();

	std::string creationFlags = std::to_string(dwCreationFlags);
	output = WriteFile(hFile, creationFlags.c_str(), creationFlags.size(), nullptr, NULL);
	PipeSleep();

	return result;
}

extern "C" __declspec(dllexport) BOOL CreateProcessWHook(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	CheckPipe();

	const char* unhook = "unhook-CreateProcessWHook";
	bool output = WriteFile(hFile, unhook, strlen(unhook), nullptr, NULL);
	PipeSleep();

	BOOL result = CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	const char* hook = "hook-CreateProcessWHook";
	output = WriteFile(hFile, hook, strlen(hook), nullptr, NULL);
	PipeSleep();

	const char* log = "log-CreateProcessW";
	output = WriteFile(hFile, log, strlen(log), nullptr, NULL);
	PipeSleep();

	output = WriteFile(hFile, lpApplicationName, wcslen(lpApplicationName) * 2, nullptr, NULL);
	PipeSleep();

	output = WriteFile(hFile, lpCommandLine, wcslen(lpCommandLine) * 2, nullptr, NULL);
	PipeSleep();

	std::string creationFlags = std::to_string(dwCreationFlags);
	output = WriteFile(hFile, creationFlags.c_str(), creationFlags.size(), nullptr, NULL);
	PipeSleep();

	return result;
}

extern "C" __declspec(dllexport) int MessageBoxWHook(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	CheckPipe();

	const char* unhook = "unhook-MessageBoxWFake";
	bool output = WriteFile(hFile, unhook, strlen(unhook), nullptr, NULL);
	PipeSleep();

	/*MessageBox(NULL, L"TEXT!", L"MY CAPTION!", 0);
	MessageBox(hWnd, lpText, lpCaption, uType);*/

	const char* hook = "hook-MessageBoxWFake";
	output = WriteFile(hFile, hook, strlen(hook), nullptr, NULL);
	PipeSleep();

	const char* log = "log-MessageBoxW";
	output = WriteFile(hFile, log, strlen(log), nullptr, NULL);
	PipeSleep();

	WriteFile(hFile, lpText, wcslen(lpText) * 2, nullptr, NULL);
	PipeSleep();

	return 1;
}