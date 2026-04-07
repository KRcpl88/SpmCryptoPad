#include "../CryptoPad/framework.h"
#include "CryptoPadUtils.h"

char ctoh(char c)
{
    if (('0' <= c) && ('9' >= c))
    {
        return c - '0';
    }
    else if (('a' <= c) && ('z' >= c))
    {
        return 10 + c - 'a';
    }
    else if (('A' <= c) && ('Z' >= c))
    {
        return 10 + c - 'A';
    }

    return 0;
}

unsigned long atoh(__in_z const char* pszText)
{
    unsigned long dwResult = 0;
    while (*pszText >= '0')
    {
        dwResult = (dwResult << 4) + ctoh(*pszText);
        ++pszText;
    }

    return dwResult;
}

void HexToBin(__inout_z char* pszHex, __in size_t cchBin, __out_ecount(cchBin) unsigned char* pBin)
{
    char* pszTemp = nullptr;
    size_t i = cchBin - 1;

    // start at the end
    pszTemp = pszHex + strlen(pszHex) - 2;
    while ((pszTemp > pszHex) && (i < cchBin))
    {
        pBin[i] = static_cast<unsigned char>(atoh(pszTemp));
        *pszTemp = 0;
        pszTemp -= 2;
        --i;
    }

    // convert the last char, this may be a partial value (one nybble instead of two)
    if (i < cchBin)
    {
        pBin[i] = static_cast<unsigned char>(atoh(pszHex));
        while ((--i) < cchBin)
        {
            pBin[i] = 0;
        }
    }
}

void HexToBin(__inout_z char* pszHex, __in size_t nAlign, __out size_t* pcchBin, __out unsigned char** ppBin)
{
    *pcchBin = strlen(pszHex) / 2;
    if ((((*pcchBin) / nAlign) * nAlign) < (*pcchBin))
    {
        *pcchBin = (1 + ((*pcchBin) / nAlign)) * nAlign;
    }

    *ppBin = new unsigned char[*pcchBin];

    HexToBin(pszHex, *pcchBin, *ppBin);
}

void GenNonce(__inout_bcount(k_cSpmBlockSizeBytes) BYTE* pNonce, __inout_z char* pszHashKey)
{
    char szDefaultHashKey[65] = "3BCC8CBF2103DDC295E70BCC305C6BB232479DD2792204A2CA83CE3BEFF9EA43";
    BYTE rgHashKey[4 * sizeof(SPM_WORD)] = { 0 };
    FBC_CRYPT* pFbcOneWayHash = new FBC_CRYPT();
    BYTE* pBuf = new BYTE[k_cSpmBlockSizeBytes];
    FILETIME ft = { 0 };

    *reinterpret_cast<clock_t*>(pNonce) = clock();
    size_t i = sizeof(clock_t);

    *reinterpret_cast<ULONGLONG*>(pNonce + i) = GetTickCount64();
    i += sizeof(ULONGLONG);

    ::GetSystemTimeAsFileTime(&ft);
    *reinterpret_cast<DWORD*>(pNonce + i) = ft.dwLowDateTime;
    i += sizeof(DWORD);
    *reinterpret_cast<DWORD*>(pNonce + i) = ft.dwHighDateTime;
    i += sizeof(DWORD);

    *reinterpret_cast<DWORD*>(pNonce + i) = GetCurrentProcessId();
    i += sizeof(DWORD);

    *reinterpret_cast<DWORD*>(pNonce + i) = GetCurrentThreadId();
    i += sizeof(DWORD);

    ::memcpy(pBuf, pNonce, k_cSpmBlockSizeBytes);

    // apply one way hash to the nonce so we dont leak info in the nonce
    if (pszHashKey == nullptr)
    {
        ::HexToBin(szDefaultHashKey, 4 * sizeof(SPM_WORD), rgHashKey);
    }
    else
    {
        ::HexToBin(pszHashKey, 4 * sizeof(SPM_WORD), rgHashKey);
    }

    pFbcOneWayHash->SetKeys(rgHashKey, 4 * sizeof(SPM_WORD));
    pFbcOneWayHash->Encrypt(pBuf, k_cSpmBlockSizeBytes);
    ::memcpy(pNonce, pBuf, k_cSpmBlockSizeBytes / 2);
    pFbcOneWayHash->Encrypt(pBuf, k_cSpmBlockSizeBytes);
    ::memcpy(pNonce + k_cSpmBlockSizeBytes / 2, pBuf + k_cSpmBlockSizeBytes / 2, k_cSpmBlockSizeBytes / 2);

    delete pFbcOneWayHash;
    delete[] pBuf;
}

// Apply Nonce will set keys on pCryptor
// use the real key to encrypt the nonce to create a temporary key for this file
void ApplyNonce(__inout_bcount(k_cSpmBlockSizeBytes) BYTE* pNonce, __in_bcount(cKey) const unsigned char* pKey, __in size_t cKey, __inout FBC_CRYPT* pCryptor)
{
    FBC_CRYPT OneWayHash;
    unsigned char rgTemp[k_cSpmBlockSizeBytes] = { 0 };

    ASSERT(cKey == pCryptor->s_GetKeyWidth());

    OneWayHash.SetKeys(pKey, cKey);

    ::memcpy(rgTemp, pNonce, k_cSpmBlockSizeBytes);
    OneWayHash.Encrypt(rgTemp, k_cSpmBlockSizeBytes);

    pCryptor->SetKeys(rgTemp, cKey);
}

void FbcProcessFile(__in HANDLE hFileIn, __in HANDLE hFileOut, __in ULONGLONG cbFileSize, __inout FBC_CRYPT* pCyptor, __in EFileCryptProcess eFileCryptProcess)
{
    unsigned char rgBuf[0x20000] = { 0 };
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    DWORD cbBytesToWrite = 0;
    DWORD cbBlockAlignedBytesRead = 0;
    ULONGLONG ullTotalBytes = 0;

    C_ASSERT((sizeof(rgBuf) % k_cSpmBlockSizeBytes) == 0);

    do
    {

        ReadFile(hFileIn, rgBuf, sizeof(rgBuf), &dwBytesRead, NULL);

        if (0 < dwBytesRead)
        {
            cbBlockAlignedBytesRead = (((dwBytesRead - 1) / k_cSpmBlockSizeBytes) + 1) * k_cSpmBlockSizeBytes;

            ASSERT(cbBlockAlignedBytesRead <= sizeof(rgBuf));

            switch (eFileCryptProcess)
            {
            case EFCP_Encrypt:
                pCyptor->Encrypt(rgBuf, cbBlockAlignedBytesRead);
                cbBytesToWrite = cbBlockAlignedBytesRead;
                break;
            case EFCP_Decrypt:
                pCyptor->Decrypt(rgBuf, cbBlockAlignedBytesRead);
                cbBytesToWrite = (DWORD)(min((ULONGLONG)dwBytesRead, cbFileSize - ullTotalBytes));
                break;
            }

            WriteFile(hFileOut, rgBuf, cbBytesToWrite, &dwBytesWritten, NULL);
            if (cbBytesToWrite != dwBytesWritten)
            {
                ::MessageBoxW(nullptr, L"Could not write file", L"Write Failed", MB_OK | MB_ICONERROR);
                return;
            }

            ullTotalBytes += dwBytesWritten;
        }
    } while (dwBytesRead == sizeof(rgBuf));
}

void FbcEncryptFile(__in_z LPCWSTR pwszPlaintext, __in_z LPCWSTR pwszCiphertext, __in_bcount(cbKey) const unsigned char* pKey, __in size_t cbKey)
{
    FBC_CRYPT prngCrypt;
    HANDLE hFileIn = NULL;
    HANDLE hFileOut = NULL;
    BOOL fOK = FALSE;
    unsigned char* pNonce = NULL;
    DWORD dwBytes = 0;
    DWORD cbFileSize = 0;
    LARGE_INTEGER llFileSize = { 0 };

    // open input and output files
    hFileIn = ::CreateFileW(pwszPlaintext, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFileIn)
    {
        goto Error;
    }

    fOK = GetFileSizeEx(hFileIn, reinterpret_cast<LARGE_INTEGER*>(&llFileSize));
    if ((!fOK))
    {
        goto Error;
    }

    cbFileSize = llFileSize.LowPart;


    hFileOut = ::CreateFileW(pwszCiphertext, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFileOut)
    {
        goto Error;
    }

    pNonce = new unsigned char[k_cSpmBlockSizeBytes];
    GenNonce(pNonce);

    fOK = ::WriteFile(hFileOut, pNonce, static_cast<DWORD>(k_cSpmBlockSizeBytes * sizeof(*pNonce)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != (k_cSpmBlockSizeBytes * sizeof(*pNonce))))
    {
        goto Error;
    }

    fOK = ::WriteFile(hFileOut, &cbFileSize, static_cast<DWORD>(sizeof(cbFileSize)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != sizeof(cbFileSize)))
    {
        goto Error;
    }

    ApplyNonce(pNonce, pKey, cbKey, &prngCrypt);

    FbcProcessFile(hFileIn, hFileOut, cbFileSize, &prngCrypt, EFCP_Encrypt);

    goto Done;

Error:
    ::MessageBoxW(nullptr, L"Could not encrypt file", L"Encrypt Failed", MB_OK | MB_ICONERROR);

Done:
    delete[] pNonce;
    ::CloseHandle(hFileIn);
    ::CloseHandle(hFileOut);
}

void FbcDecryptFile(__in_z LPCWSTR pwszCiphertext, __in_z LPCWSTR pwszPlaintext, __in_bcount(cbKey) const unsigned char* pKey, __in size_t cbKey)
{
    FBC_CRYPT prngCrypt;
    HANDLE hFileIn = NULL;
    HANDLE hFileOut = NULL;
    BOOL fOK = FALSE;
    unsigned char* pNonce = NULL;
    DWORD dwBytes = 0;
    DWORD cbFileSize = 0;


    // open input and output files
    hFileIn = ::CreateFileW(pwszCiphertext, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFileIn)
    {
        goto Error;
    }

    hFileOut = ::CreateFileW(pwszPlaintext, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFileOut)
    {
        goto Error;
    }

    // read nonce from input file
    pNonce = new unsigned char[k_cSpmBlockSizeBytes];

    fOK = ::ReadFile(hFileIn, pNonce, static_cast<DWORD>(k_cSpmBlockSizeBytes * sizeof(*pNonce)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != (k_cSpmBlockSizeBytes * sizeof(*pNonce))))
    {
        goto Error;
    }

    fOK = ::ReadFile(hFileIn, &cbFileSize, static_cast<DWORD>(sizeof(cbFileSize)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != sizeof(cbFileSize)))
    {
        goto Error;
    }

    ApplyNonce(pNonce, pKey, cbKey, &prngCrypt);

    FbcProcessFile(hFileIn, hFileOut, cbFileSize, &prngCrypt, EFCP_Decrypt);
    goto Done;

Error:
    ::MessageBoxW(nullptr, L"Could not decrypt file", L"Decrypt Failed", MB_OK | MB_ICONERROR);

Done:
    delete[] pNonce;
    ::CloseHandle(hFileIn);
    ::CloseHandle(hFileOut);
}

void ParsePasswordW(__in_z LPCWSTR pwszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin)
{
    size_t i = 0;
    bool fFirstPass = true;
    bool fPasswordIncomplete = true;
    LPCWSTR pwszTemp = nullptr;

    *ppBin = new unsigned char[cbBin];
    ::memset(*ppBin, 0, cbBin);

    pwszTemp = pwszPassword;

    while (fFirstPass || ((*pwszTemp) && fPasswordIncomplete))
    {
        if ((*pwszTemp) == 0)
        {
            pwszTemp = pwszPassword;
        }

        *(reinterpret_cast<WCHAR*>(*ppBin + i)) += *pwszTemp;
        ++pwszTemp;

        if ((*pwszTemp) == 0)
        {
            fPasswordIncomplete = false;
        }

        i += sizeof(*pwszTemp);
        if (i >= cbBin)
        {
            fFirstPass = false;
            i = 0;
        }
    }
}

void ParsePasswordA(__in_z LPCSTR pszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin)
{
    size_t i = 0;
    bool fFirstPass = true;
    bool fPasswordIncomplete = true;
    LPCSTR pszTemp = nullptr;

    *ppBin = new unsigned char[cbBin];
    ::memset(*ppBin, 0, cbBin);

    pszTemp = pszPassword;

    while (fFirstPass || ((*pszTemp) && fPasswordIncomplete))
    {
        if ((*pszTemp) == 0)
        {
            pszTemp = pszPassword;
        }

        *(*ppBin + i) += static_cast<unsigned char>(*pszTemp);
        ++pszTemp;

        if ((*pszTemp) == 0)
        {
            fPasswordIncomplete = false;
        }

        i += sizeof(*pszTemp);
        if (i >= cbBin)
        {
            fFirstPass = false;
            i = 0;
        }
    }
}
