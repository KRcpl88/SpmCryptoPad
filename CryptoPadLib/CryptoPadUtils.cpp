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
