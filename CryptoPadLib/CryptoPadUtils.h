#pragma once

#include "../CryptoPad/framework.h"
#include "SpmBlockCipher64.h"

char ctoh(char c);
unsigned long atoh(__in_z const char* pszText);
void HexToBin(__inout_z char* pszHex, __in size_t cchBin, __out_ecount(cchBin) unsigned char* pBin);
void HexToBin(__inout_z char* pszHex, __in size_t nAlign, __out size_t* pcchBin, __out unsigned char** ppBin);
void GenNonce(__inout_bcount(k_cSpmBlockSizeBytes) BYTE* pNonce, __inout_z char* pszHashKey = nullptr);
void ApplyNonce(__inout_bcount(k_cSpmBlockSizeBytes) BYTE* pNonce, __in_bcount(cKey) const unsigned char* pKey, __in size_t cKey, __inout FBC_CRYPT* pCryptor);
void FbcProcessFile(__in HANDLE hFileIn, __in HANDLE hFileOut, __in ULONGLONG cbFileSize, __inout FBC_CRYPT* pCryptor, __in EFileCryptProcess eFileCryptProcess);
void FbcEncryptFile(__in_z LPCWSTR pwszPlaintext, __in_z LPCWSTR pwszCiphertext, __in_bcount(cbKey) const unsigned char* pKey, __in size_t cbKey);
void FbcDecryptFile(__in_z LPCWSTR pwszCiphertext, __in_z LPCWSTR pwszPlaintext, __in_bcount(cbKey) const unsigned char* pKey, __in size_t cbKey);
void ParsePasswordW(__in_z LPCWSTR pwszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin);
void ParsePasswordA(__in_z LPCSTR pszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin);
