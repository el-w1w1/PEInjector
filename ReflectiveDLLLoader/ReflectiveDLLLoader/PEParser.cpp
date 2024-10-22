#include "Imports.h"

/* converts rva to va*/
DWORD rvaConv(DWORD rva, _IMAGE_NT_HEADERS64* nt_header) {

	auto sect = IMAGE_FIRST_SECTION(nt_header);
	UINT i;
	for (i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
		//cout << "[+] section name : " << sect->Name << endl;
		if (sect->VirtualAddress > rva) {
			break;
		}
		sect++;
	}
	sect--;
	return rva - sect->VirtualAddress + sect->PointerToRawData;
}
void PEParserMonster() {
	/* open file locally (can replace with pulled from memory */

	string dllpath = "C:\\Users\\ashev\\source\\repos\\ReflectiveDLLLoader\\x64\\Debug\\injectDLL.dll";
	//string dllpath = "C:\\Windows\\System32\\kernel32.dll"; 
	fstream dllfile;
	char* dllbase;
	dllfile.open(dllpath, std::ios::in | std::ios::binary | std::ios::ate);
	if (!dllfile.is_open()) {
		cout << "file not found at location: " << dllpath << endl;
		dllfile.close();
		return;
	}
	auto size = dllfile.tellg();
	dllbase = new char[size];
	dllfile.seekg(0, std::ios::beg);
	dllfile.read(dllbase, size);

	/* find sizeOfImage*/
	/* raw offset method */
	byte a = *(dllbase + 0x3c);
	char* ptr = (dllbase + (int)a + 0x50);

	DWORD imgSize = (*(DWORD*)ptr);

	/* with proper structs */
	_IMAGE_DOS_HEADER* dos = reinterpret_cast<_IMAGE_DOS_HEADER*>(dllbase);
	cout << dos->e_lfanew << endl;
	long nt_offset = dos->e_lfanew;

	_IMAGE_NT_HEADERS64* nt_header = reinterpret_cast<_IMAGE_NT_HEADERS64*>(dllbase + nt_offset);

	DWORD imgSize2 = nt_header->OptionalHeader.SizeOfImage;

	cout << "[+] Size of Image: " << imgSize << endl;
	cout << "[+] Size of Image from struct: " << imgSize2 << endl;
	//cout << hex << setfill('0') << setw(2) <<  memblock[0x3c];
	DWORD datadir = nt_header->OptionalHeader.DataDirectory[1].VirtualAddress;
	// loop through all sections
	//DWORD entrypt = nt_header->OptionalHeader.AddressOfEntryPoint; 
	_IMAGE_SECTION_HEADER* sect = IMAGE_FIRST_SECTION(nt_header); // nt_header + offset to optionalheader + sizeofoptionalheader = section header 
	//cout << FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader << endl;
	UINT i;
	for (i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
		cout << "[+] section name : " << sect->Name << endl;
		if (sect->VirtualAddress > datadir) {
			break;
		}
		sect++;
	}
	// some error check maybe? 
	sect--;
	DWORD datarva = datadir - sect->VirtualAddress + sect->PointerToRawData;


	/* parse IDT for each DLLs imports */
	_IMAGE_IMPORT_DESCRIPTOR* idt = reinterpret_cast<_IMAGE_IMPORT_DESCRIPTOR*>(dllbase + datarva);
	// get name of dll 
	char* secname;
	while (idt->Name != 0) {
		secname = ((idt->Name - sect->VirtualAddress + sect->PointerToRawData) + dllbase);
		cout << "[+] dll name: " << secname << endl;
		if (idt->TimeDateStamp == 0) {
			cout << "  [+] dll is not bound" << endl;
		}
		else {
			cout << "  [+] dll is bound" << endl;
		}
		DWORD import_offset;
		IMAGE_IMPORT_BY_NAME* namestruct;
		DWORD thunk = idt->FirstThunk;
		do {
			import_offset = *reinterpret_cast<DWORD*>((thunk - sect->VirtualAddress + sect->PointerToRawData) + dllbase);
			/* stops loop when data zero'd out (probably cleaner way to do this)*/
			if (import_offset == 0) {
				break;
			}
			namestruct = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>((import_offset - sect->VirtualAddress + sect->PointerToRawData) + dllbase);
			// cleaner way DWORD import_offset = (*(DWORD*)(blah));
			cout << "  [+] exported function: " << namestruct->Name << endl;
			thunk = thunk + 8;

		} while (true);

		idt++;


	}
	//idt--;

	/* parsing base relocations*/
	sect = IMAGE_FIRST_SECTION(nt_header); // nt_header 
	/* find .reloc*/
	for (i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
		cout << "[+] section name : " << sect->Name << endl;
		auto s = (char*)sect->Name;
		/* p sure unnecessary bc reloc is always last but whatevs */
		if (strcmp(s, ".reloc") == 0) {
			cout << "RELOC FOUND" << endl;
			break;
		}
		sect++;
	}
	DWORD relocaddr = nt_header->OptionalHeader.DataDirectory[5].VirtualAddress;
	DWORD relocrva = relocaddr - sect->VirtualAddress + sect->PointerToRawData;
	_IMAGE_BASE_RELOCATION* reloc = reinterpret_cast<_IMAGE_BASE_RELOCATION*>(relocrva + dllbase);

	WORD type, offset;
	while (reloc->SizeOfBlock != 0) {
		cout << "[+] size of reloc block: " << reloc->SizeOfBlock << "with RVA: " << reloc->VirtualAddress << endl;

		// get them relocs 
		WORD* addr = (WORD*)(reloc + 1);
		/* calculating amount of entries */
		DWORD entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		cout << " ### NUMBER OF ENTRIES : " << entries << endl;
		for (UINT i = 0; entries > i; i++, addr++) {
			if (*addr == 0) {
				cout << "padding entry" << endl;
				break;
			}
			// get 0-4 bits for reloc type 
			// 1111 0000 1111 0000 
			// -> right shift 12 = 0000 0000 0000 1111 
			type = *addr >> 12;
			cout << "[+] type: " << std::dec << type << endl;

			// bits 4-12 (offset)
			// can just AND with 0000 1111 1111 1111 
			offset = *addr & 0x0FFF;
			cout << "[+] offset: " << hex << offset << " with actual address at: " << reloc->VirtualAddress + offset << endl;
			DWORD actualOffset = rvaConv(reloc->VirtualAddress + offset, nt_header);
			auto addr2 = (PVOID*)(dllbase + actualOffset);
			BYTE* badaddr = reinterpret_cast<BYTE*>(*addr2);
			ULONG64 newbase = (ULONG64)dllbase;
			PVOID goodaddr = (PVOID)((badaddr - nt_header->OptionalHeader.ImageBase) + newbase);
			*addr2 = goodaddr;
			cout << "[+] bad addr: " << (VOID*)badaddr << " replaced with: " << goodaddr << endl;
		}
		reloc = reinterpret_cast<_IMAGE_BASE_RELOCATION*>(((BYTE*)reloc) + reloc->SizeOfBlock);
	}

	/* cleanup */
	delete[] dllbase;
	dllfile.close();
}
