// Testing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <winternl.h> 
#pragma comment(lib, "ntdll")

void PebWalker() {
    _PROCESS_BASIC_INFORMATION info = { 0 }; 
    NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &info, sizeof(_PROCESS_BASIC_INFORMATION), NULL);
    std::cout << "Peb Address" << info.PebBaseAddress << std::endl;

    PEB* pebby = (PEB*)(info.PebBaseAddress); 
    std::cout << "Image base address: " << pebby->Reserved3[1] << std::endl;
    LDR_DATA_TABLE_ENTRY* f = (LDR_DATA_TABLE_ENTRY*)(pebby->Ldr->InMemoryOrderModuleList.Flink);
}       

int main()
{
    PebWalker();
    std::cout << "Hello World!\n";
}
