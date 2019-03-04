#ifndef _LOADER
#define _LOADER

#ifdef __cplusplus
extern "C" {
#endif

LPVOID GetEntryPoint(HMODULE);
HMODULE WriteDllIntoProcess(HMODULE);
LPVOID GetExportedFunction(LPVOID, LPCSTR);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // _LOADER