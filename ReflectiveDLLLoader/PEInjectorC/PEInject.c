#include <stdio.h>
#include <Windows.h>
#include <strsafe.h>


void printWinapiErr(LPCTSTR lpszFunction)
{
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    DWORD dw = GetLastError();

    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpMsgBuf,
        0, NULL);
    SetConsoleOutputCP(CP_UTF8); 
    printf("%ws", (LPWSTR)lpMsgBuf);

    return; 
}


/* reads in filename and returns true if successful (WINAPI WAY) */
BOOL readFile(IN LPCSTR cFileName, OUT PBYTE* ppBuffer, OUT PDWORD pdwFileSize) {
	/* init values */
	HANDLE      hFile = INVALID_HANDLE_VALUE;
	PBYTE       pBufer = NULL;
	DWORD       dwFileSize = 0x00, dwNumberOfBytesRead = 0x00;
	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        printWinapiErr(L"CreateFileA");
        goto _FUNC_CLEANUP;
	} 

    if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
        printWinapiErr(L"GetFileSize"); 
        goto _FUNC_CLEANUP;
    }

    if ((pBufer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize)) == NULL) {
        printWinapiErr(L"HeapAlloc");
        goto _FUNC_CLEANUP;
    }

    if (!ReadFile(hFile, pBufer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
        printWinapiErr(L"ReadFile"); 
        goto _FUNC_CLEANUP; 
    }

    *ppBuffer = pBufer; 
    *pdwFileSize = dwFileSize; 

_FUNC_CLEANUP: 
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile); 
    }
    if (!*ppBuffer && pBufer)
        HeapFree(GetProcessHeap(), 0x00, pBufer);
    return ((*ppBuffer != NULL) && (*pdwFileSize != 0x00)) ? TRUE : FALSE;
}
/* C way */
BOOL readFileC(IN char* cFileName, OUT BYTE* fbuf, OUT long* fsize)
{
    FILE* fptr; 
    errno_t err; 
    if ((err = fopen_s(&fptr, cFileName, "rb")) != 0) {
        char d[50]; 
        strerror_s(d, err, NULL);
        printf("not able to open file: %s : %s\n", cFileName, d); 
        return FALSE; 
    }
    /* check length and malloc */
    fseek(fptr, 0L, SEEK_END); 
    long fileSize = ftell(fptr); 
 
    BYTE* fileBuf = malloc(fileSize);
    if (fileBuf == 0) {
        fclose(fptr);
        printf("malloc of size %ld failed\n", fileSize); 
        return FALSE; 
    }
    /* read contents*/
    rewind(fptr); 
    size_t a = fread(fileBuf, sizeof(BYTE), fileSize, fptr);
    if (a != fileSize) {
        printf("fread failed with code %d\n", ferror(fptr));
        fclose(fptr); 
        return FALSE; 
    }

    fsize = fileSize; 
    fbuf = fileBuf; 
    return TRUE; 
}

typedef struct _PE_HDRS
{
    PBYTE                    pFileBuffer;
    DWORD                    dwFileSize;

    PIMAGE_NT_HEADERS        pImgNtHdrs;
    PIMAGE_SECTION_HEADER    pImgSecHdr;

    PIMAGE_DATA_DIRECTORY    pEntryImportDataDir;
    PIMAGE_DATA_DIRECTORY    pEntryBaseRelocDataDir;
    PIMAGE_DATA_DIRECTORY    pEntryTLSDataDir;
    PIMAGE_DATA_DIRECTORY    pEntryExceptionDataDir;
    PIMAGE_DATA_DIRECTORY    pEntryExportDataDir;

    BOOL                     bIsDLLFile;

} PE_HDRS, * PPE_HDRS;

/* initializes PE_Hdrs*/
BOOL InitializePeStruct(OUT PPE_HDRS pPeHdrs, IN PBYTE pFileBuffer, IN DWORD dwFileSize) {
    /* error checking */
    if (!pPeHdrs || !pFileBuffer || !dwFileSize) {
        return FALSE; 
    }

    /* assign values */
    pPeHdrs->pFileBuffer = pFileBuffer; 
    pPeHdrs->dwFileSize = dwFileSize; 
    pPeHdrs->pImgNtHdrs = (PIMAGE_NT_HEADERS)(pFileBuffer + ((PIMAGE_DOS_HEADER)pFileBuffer)->e_lfanew);
    pPeHdrs->pImgSecHdr = IMAGE_FIRST_SECTION(pPeHdrs->pImgNtHdrs);
    pPeHdrs->pEntryImportDataDir = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; 
    pPeHdrs->pEntryBaseRelocDataDir = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    pPeHdrs->pEntryTLSDataDir = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    pPeHdrs->pEntryExceptionDataDir = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    pPeHdrs->pEntryExportDataDir = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    return TRUE; 

}

BOOL AllocateAndCopy(IN PPE_HDRS pPeHdrs, OUT PBYTE* pPeBaseAddrOut ) {

    DWORD size = pPeHdrs->pImgNtHdrs->OptionalHeader.SizeOfImage;
    PBYTE pPeBaseAddr = NULL;
    if (( pPeBaseAddr = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL) {
        printWinapiErr(L"VirtualAlloc"); 
        return FALSE; 
    }
    /* Loop through and copy sections */
    for (int i = 0; i < pPeHdrs->pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        PVOID dst = pPeBaseAddr + pPeHdrs->pImgSecHdr[i].VirtualAddress; 
        PVOID src = pPeHdrs->pFileBuffer + pPeHdrs->pImgSecHdr[i].PointerToRawData;
        DWORD size = pPeHdrs->pImgSecHdr[i].SizeOfRawData; 
        memcpy(dst, src, size); 
    }

    *pPeBaseAddrOut = pPeBaseAddr; 
    return TRUE; 
}

typedef struct _BASE_RELOCATION_ENTRY {
    WORD	Offset : 12;  // Specifies where the base relocation is to be applied.
    WORD	Type : 4;   // Indicates the type of base relocation to be applied.
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


BOOL FixReloc(IN PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir, IN ULONG_PTR pPeBaseAddress, IN ULONG_PTR pPreferableAddress) {
    // Pointer to the beginning of the base relocation block.
    PIMAGE_BASE_RELOCATION pImgBaseRelocation = (pPeBaseAddress + pEntryBaseRelocDataDir->VirtualAddress);

    // The difference between the current PE image base address and its preferable base address.
    ULONG_PTR uDeltaOffset = pPeBaseAddress - pPreferableAddress;

    // Pointer to individual base relocation entries.
    PBASE_RELOCATION_ENTRY pBaseRelocEntry = NULL;
    // Iterate through all the base relocation blocks.
    while (pImgBaseRelocation->VirtualAddress) {

        // Pointer to the first relocation entry in the current block.
        pBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1);

        // Iterate through all the relocation entries in the current block.
        while ((PBYTE)pBaseRelocEntry != (PBYTE)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock) {
            // Process the relocation entry based on its type.
            switch (pBaseRelocEntry->Type) {
            case IMAGE_REL_BASED_DIR64:
                // Adjust a 64-bit field by the delta offset.
                *((ULONG_PTR*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += uDeltaOffset;
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                // Adjust a 32-bit field by the delta offset.
                *((DWORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += (DWORD)uDeltaOffset;
                break;
            case IMAGE_REL_BASED_HIGH:
                // Adjust the high 16 bits of a 32-bit field.
                *((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += HIWORD(uDeltaOffset);
                break;
            case IMAGE_REL_BASED_LOW:
                // Adjust the low 16 bits of a 32-bit field.
                *((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += LOWORD(uDeltaOffset);
                break;
            case IMAGE_REL_BASED_ABSOLUTE:
                // No relocation is required.
                break;
            default:
                // Handle unknown relocation types.
                printf("[!] Unknown relocation type: %d | Offset: 0x%08X \n", pBaseRelocEntry->Type, pBaseRelocEntry->Offset);
                return FALSE;
            }
            // Move to the next relocation entry.
            pBaseRelocEntry++;
        }

        // Move to the next relocation block.
        pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)pBaseRelocEntry;
    }


    return TRUE; 
}

BOOL FixImportAddressTable(IN PIMAGE_DATA_DIRECTORY pEntryImportDataDir, IN PBYTE pPeBaseAddress) {

    /* get image_import_descriptor -> will list all dlls to import */
    PIMAGE_IMPORT_DESCRIPTOR pImgDescriptor = NULL;

    // loop through imp_desc
    for (size_t i = 0; i < pEntryImportDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

        // get current image_import_descriptor
        pImgDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pPeBaseAddress + pEntryImportDataDir->VirtualAddress + i);

        // reached end when both null 
        if (pImgDescriptor->FirstThunk == NULL && pImgDescriptor->OriginalFirstThunk == NULL) {
            break; 
        }

        LPSTR cDllName = (LPSTR)(pPeBaseAddress + pImgDescriptor->Name); 
        ULONG_PTR uOriginalFirstThunkRVA = pImgDescriptor->OriginalFirstThunk; 
        ULONG_PTR uFirstThunkRVA = pImgDescriptor->FirstThunk; 
        SIZE_T ImgThunkSize = 0x00; // iterate through IAT & INT 

        HMODULE hModule = NULL; 

        if (!(hModule = LoadLibraryA(cDllName))) {
            printWinapiErr(L"LoadLibraryA"); 
            return FALSE; 
        }

        /* Iterate over loaded DLL & resolve funcs*/
        while (TRUE) {

            // get first thunk (IAT) and orig first thunk (INT)
            PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddress + uOriginalFirstThunkRVA + ImgThunkSize); 
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddress + uFirstThunkRVA + ImgThunkSize); 
            ULONG_PTR pFuncAddress = NULL; 

            // first thunk and orig thunk same rn but need to use INT to path IAT 

            // break when end of THUNK (no more funcs to resolve) 
            if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL) {
                break; 
            }


            // import by ordinal or func name 
            if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {
                if (!(pFuncAddress = GetProcAddress(hModule, IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal))) ){
                    printf("Can't import !%s#%d \n", cDllName, (int)pOriginalFirstThunk->u1.Ordinal); 
                    return FALSE; 
                }
            } // import function by name 
            else {
                PIMAGE_IMPORT_BY_NAME pImgName = (PIMAGE_IMPORT_BY_NAME)(pPeBaseAddress + pOriginalFirstThunk->u1.AddressOfData); 
                if (!(pFuncAddress = GetProcAddress(hModule, pImgName->Name))) {
                    printf("Could not Import !%s.%s \n", cDllName, pImgName->Name); 
                    return FALSE; 
                }
            }

            // set function addr in IAT 
            pFirstThunk->u1.Function = (ULONGLONG)pFuncAddress; 

            // move to next func in IAT/INT arr 
            ImgThunkSize += sizeof(IMAGE_THUNK_DATA); 
        }


    }
    return TRUE; 
}

BOOL FixMemPermissions(IN PBYTE pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) {

    // loop through each section 
    for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        DWORD dwProtection = 0x00, dwOldProtection = 0x00; 

        // skip if empty 
        if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress) {
            continue; 
        }

        /* determine mem protections */
        DWORD secchar = pImgSecHdr[i].Characteristics;

        /* big if for all vals */
        if (secchar & IMAGE_SCN_MEM_WRITE)
            dwProtection = PAGE_WRITECOPY;
        if (secchar & IMAGE_SCN_MEM_READ)
            dwProtection = PAGE_READONLY;
        if (secchar & IMAGE_SCN_MEM_EXECUTE)
            dwProtection = PAGE_EXECUTE;    
        if ((secchar & IMAGE_SCN_MEM_READ) && (secchar & IMAGE_SCN_MEM_WRITE))
            dwProtection = PAGE_READWRITE; 
        if ((secchar & IMAGE_SCN_MEM_READ) && (secchar & IMAGE_SCN_MEM_EXECUTE))
            dwProtection = PAGE_EXECUTE_READ;
        if ((secchar & IMAGE_SCN_MEM_EXECUTE) && (secchar & IMAGE_SCN_MEM_WRITE))
            dwProtection = PAGE_EXECUTE_WRITECOPY;
        if ((secchar & IMAGE_SCN_MEM_READ) && (secchar & IMAGE_SCN_MEM_WRITE) && (secchar & IMAGE_SCN_MEM_EXECUTE))
            dwProtection = PAGE_EXECUTE_READWRITE;

        /* virtual protect the area of mem */
        if (!VirtualProtect((PVOID)(pPeBaseAddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData, dwProtection, &dwOldProtection)) {
            printWinapiErr(L"VirtualProtect");
            return FALSE; 
        }


    }
    return TRUE;
}


BOOL LocalPeExec(IN PPE_HDRS pPeHdrs) {
    //BYTE PeBaseAddr = { 0 };
    PBYTE pPeBaseAddr = NULL; 
    if (!AllocateAndCopy(pPeHdrs, &pPeBaseAddr)) {
        printf("AddressAndCopy failed\n"); 
        return FALSE; 
    }
    if(!FixReloc(pPeHdrs->pEntryBaseRelocDataDir, pPeBaseAddr, pPeHdrs->pImgNtHdrs->OptionalHeader.ImageBase)) {
        return FALSE; 
    }
    if (!FixImportAddressTable(pPeHdrs->pEntryImportDataDir, pPeBaseAddr)) {
        return FALSE; 
    }

    if (!FixMemPermissions(pPeBaseAddr, pPeHdrs->pImgNtHdrs, pPeHdrs->pImgSecHdr)) {
        return FALSE; 
    }

    PBYTE entryPt = pPeHdrs->pImgNtHdrs->OptionalHeader.AddressOfEntryPoint + pPeBaseAddr;
    /* executing DLL */
    if ((pPeHdrs->pImgNtHdrs->FileHeader.Characteristics & 0x2000) == 0x2000) {
        printf("[+] IS DLL");
        typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
        DLLMAIN pDllMain = (DLLMAIN)entryPt; 
        pDllMain((HINSTANCE)pPeBaseAddr, DLL_PROCESS_ATTACH, NULL); 
    } /* executing EXE */
    else {
        typedef BOOL(WINAPI* MAIN)(); 
        MAIN pMain = (MAIN)entryPt; 
        pMain(); 
        printf("[+] IS EXE");
    }
}



/* Maldev Local PE Loader (prelude to DLL equivalent) */
void PELoader() {
/* read in PE file (can replace w network comm) */
    PBYTE fileBuf = 0;
    DWORD fileSz = 0; 
    if (!readFile("C:\\Windows\\System32\\calc.exe", &fileBuf, &fileSz)) {
        printf("failed to read file\n"); 
        return; 
    }
    
    PE_HDRS pe_hdr = { 0 };
    if (!InitializePeStruct(&pe_hdr, fileBuf, fileSz)) {
        printf("failed to init PE struct\n"); 
        return; 
    }
    LocalPeExec(&pe_hdr); 
	return;
}

int main() {
    PELoader(); 
}