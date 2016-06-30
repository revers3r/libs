#pragma once
#include <iostream>
#include <vector>
#include <Windows.h>

class DLLInjector {
public:
	DLLInjector(int, std::string);
	~DLLInjector();
	BOOL Inject();
private:
	int dwPID;
	std::string dll_path;
};