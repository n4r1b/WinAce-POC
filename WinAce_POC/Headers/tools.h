#ifndef _TOOLS
#define _TOOLS

#ifdef __cplusplus
extern "C" {
#endif

#define XOR_ACE_KEY 0x13
#define XOR_DLL_KEY 0x93
#define TMP_FILE "test.rar"

	typedef struct resStruc
	{
		DWORD resSize;
		LPVOID resAddress;
	} resStruc;

	typedef struct decryptedDataStruc
	{
		LPVOID decryptedData;
		DWORD sizeData;
	} decryptedDataStruc;

	resStruc GetResource(HMODULE, INT);
	LPVOID XorBytes(BYTE *, DWORD, BYTE);
	BYTE * DecryptBase64(decryptedDataStruc *, LPVOID, DWORD);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // _TOOLS