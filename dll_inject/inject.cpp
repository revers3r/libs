#include "inject.h"

DLLInjector::DLLInjector(int pid, std::string dll)
		: dwPID(pid), dll_path(dll.c_str()) {
	std::cout << "[ -> Inject DLL Process : " << dll_path.c_str() << std::endl;
}
DLLInjector::~DLLInjector() { std::cout << "[*] DLL Exit.." << std::endl; }

BOOL DLLInjector::Inject() {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE) {
		std::cerr << "[*] Error : OpenProcess().." << std::endl;
		return FALSE;
	}
	PVOID mem = VirtualAllocEx(hProcess, NULL, dll_path.length() + 1, MEM_COMMIT,
		PAGE_READWRITE);
	if (mem == NULL) {
		std::cerr << "[*] Error : VirtualAllocEx().." << std::endl;
		CloseHandle(hProcess);
		return FALSE;
	}
	if (!WriteProcessMemory(hProcess, mem, (LPCVOID)dll_path.c_str(),
		dll_path.length() + 1, NULL)) {
		std::cerr << "[*] Error : WriteProcessMemory().." << std::endl;
		VirtualFreeEx(hProcess, mem, dll_path.length() + 1, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryA"), mem, 0, NULL);
	if (hThread == INVALID_HANDLE_VALUE) {
		std::cerr << "[*] Error : CreateRemoteThread().." << std::endl;
		VirtualFreeEx(hProcess, mem, dll_path.length() + 1, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);
	std::cout << "[ -> Exit Process.." << std::endl;
	VirtualFreeEx(hProcess, mem, dll_path.length() + 1, MEM_RELEASE);
	CloseHandle(hProcess);
	return TRUE;
}