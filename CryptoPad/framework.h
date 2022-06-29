// header.h : include file for standard system include files,
// or project specific include files
//

#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <commdlg.h>
// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <ctime>
#include <strsafe.h>

#ifdef _DEBUG
#define DIAGNOSTIC_OUTPUT 1
#define ASSERT(t) {if (!(t)){DebugBreak();}}
#else
#define DIAGNOSTIC_OUTPUT 0
#define ASSERT(t) ;
#endif

enum EFileCryptProcess
{
    EFCP_Encrypt,
    EFCP_Decrypt
};

