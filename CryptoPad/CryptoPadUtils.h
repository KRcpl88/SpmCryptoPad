#pragma once

#include "framework.h"
#include "SpmBlockCipher64.h"

char ctoh(char c);
unsigned long atoh(__in_z const char* pszText);
void HexToBin(__inout_z char* pszHex, __in size_t cchBin, __out_ecount(cchBin) unsigned char* pBin);
void HexToBin(__inout_z char* pszHex, __in size_t nAlign, __out size_t* pcchBin, __out unsigned char** ppBin);
void GenNonce(__inout_bcount(k_cSpmBlockSizeBytes) BYTE* pNonce, __inout_z char* pszHashKey = nullptr);
