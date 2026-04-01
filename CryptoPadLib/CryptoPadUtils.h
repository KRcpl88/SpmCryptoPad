#pragma once

#include "../CryptoPad/framework.h"
#include "SpmBlockCipher64.h"

char ctoh(char c);
unsigned long atoh(__in_z const char* pszText);
void HexToBin(__inout_z char* pszHex, __in size_t cchBin, __out_ecount(cchBin) unsigned char* pBin);
void HexToBin(__inout_z char* pszHex, __in size_t nAlign, __out size_t* pcchBin, __out unsigned char** ppBin);
void GenNonce(__inout_bcount(k_cSpmBlockSizeBytes) BYTE* pNonce, __inout_z char* pszHashKey = nullptr);
void ParsePassword(__in_z LPCWSTR pszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin);
