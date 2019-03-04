#ifndef _ACE
#define _ACE

#ifdef __cplusplus
extern "C" {
#endif
	
	#include "STRUCTS.h"
	#include "UNACEFNC.h"
	#include "CALLBACK.h"

	extern CHAR m_CommentBuf[8192];
	extern CHAR szTmpPath[MAX_PATH];
	extern CHAR tmpFile[MAX_PATH];

	VOID DropAceResource(HMODULE);
	VOID FillInitStruct(pACEInitDllStruc);
	VOID FillExtractStruct(pACEExtractStruc);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // _ACE