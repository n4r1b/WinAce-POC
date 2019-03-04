#include <Windows.h>

#include "Headers/tools.h"
#include "Headers/resource.h"

resStruc GetResource(HMODULE hModule, INT resId) {

	resStruc resource = {};
	HRSRC hResource = NULL;
	HGLOBAL hMemory = NULL;

	hResource = FindResource(hModule, MAKEINTRESOURCE(resId), RT_RCDATA);
	hMemory = LoadResource(hModule, hResource);
	resource.resSize = SizeofResource(hModule, hResource);
	resource.resAddress = LockResource(hMemory);

	return resource;
}

LPVOID XorBytes(BYTE * dataToXor, DWORD size, BYTE hexKey) {

	LPVOID decryptedData = NULL;
	decryptedData = HeapAlloc(GetProcessHeap(), 0, size);

	for (unsigned int i = 0; i < size; i++) {
		*((BYTE *)decryptedData + i) = *(dataToXor + i) ^ hexKey;
	}
	return decryptedData;
}

BYTE * DecryptBase64(decryptedDataStruc *decryptStruc, LPVOID lpAddress, DWORD size) {

	DWORD dataLen = 0;
	LPVOID dData = NULL;
	LPVOID base64Decrypted = NULL;
	CryptStringToBinaryA((LPCSTR)lpAddress, size, CRYPT_STRING_BASE64, NULL, &dataLen, NULL, NULL);

	base64Decrypted = HeapAlloc(GetProcessHeap(), 0, dataLen);
	if (base64Decrypted) {
		CryptStringToBinaryA((LPCSTR)lpAddress, size, CRYPT_STRING_BASE64, (BYTE *)base64Decrypted, &dataLen, NULL, NULL);
		decryptStruc->sizeData = dataLen;
	}

	return (BYTE *)base64Decrypted;
}