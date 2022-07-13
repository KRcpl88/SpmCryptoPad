// CryptoPad.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "CryptoPad.h"
#include "SpmBlockCipher64.h"

#define MAX_LOADSTRING 100


// Global Variables:
HINSTANCE hInst;                                // current instance
HWND hText;                                     // text control
HWND hSearchDlg = nullptr;                      // find dialog
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
WCHAR szPassword[1024] = { 0 };

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                Run(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    AboutDlgProc(HWND, UINT, WPARAM, LPARAM);


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
    char* pszTemp;
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

void InitCodebook(char* pKeyData)
{
    size_t cKey = 0;
    unsigned char* pKey = NULL;

    HexToBin(pKeyData, 1, &cKey, &pKey);

    FBC_CRYPT::s_ConstructCodebook(CSpmBlockCipher64::BLOCK_MODE::Permutation);

    FBC_CRYPT::s_PermuteCodebook(16, pKey, cKey);
    delete[] pKey;

#ifdef _DEBUG
    FBC_CRYPT::s_CheckCodebook();
#endif
}


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize global strings
    ::LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    ::LoadStringW(hInstance, IDS_CRYPTOPAD, szWindowClass, MAX_LOADSTRING);
    ::MyRegisterClass(hInstance);

    return ::Run(hInstance, nCmdShow);
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = ::LoadIconW(hInstance, MAKEINTRESOURCE(IDI_CRYPTOPAD));
    wcex.hCursor        = ::LoadCursorW(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_CRYPTOPAD);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = ::LoadIconW(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return ::RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL Run(HINSTANCE hInstance, int nCmdShow)
{
    char szCodebook[33] = "b6a4c072764a2233db9c23b0bc79c143";

    hInst = hInstance; // Store instance handle in our global variable

    // TBD load codebook from registry
    ::InitCodebook(szCodebook);

    HWND hWnd = ::CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

    if (!hWnd)
    {
        return FALSE;
    }

    ::ShowWindow(hWnd, nCmdShow);
    ::UpdateWindow(hWnd);

    HACCEL hAccelTable = ::LoadAcceleratorsW(hInstance, MAKEINTRESOURCE(IDC_CRYPTOPAD));

    MSG msg;

    // Main message loop:
    while (::GetMessageW(&msg, nullptr, 0, 0))
    {
        if (hSearchDlg == nullptr)
        {
            if (!::TranslateAcceleratorW(msg.hwnd, hAccelTable, &msg))
            {
                ::TranslateMessage(&msg);
                ::DispatchMessageW(&msg);
            }
        }
        else
        {
            if (!IsDialogMessage(hSearchDlg, &msg))
            {
                ::TranslateMessage(&msg);
                ::DispatchMessageW(&msg);
            }
        }
    }

    return TRUE;
}

// Message handler for password dialog box.
INT_PTR CALLBACK PasswordDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    HWND hwndPassword = nullptr;
    LONG lStyle = 0;

    switch (message)
    {
    case WM_INITDIALOG:
        ::SetDlgItemTextW(hDlg, IDC_PASSWORD, szPassword);
        ::SendDlgItemMessageW(hDlg, IDC_PASSWORD, EM_LIMITTEXT, ARRAYSIZE(szPassword) - 1, 0);
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDOK:
            ::GetDlgItemText(hDlg, IDC_PASSWORD, szPassword, ARRAYSIZE(szPassword) - 1);
        case IDCANCEL:
            ::EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;

        case IDC_VISIBLE:
            hwndPassword = ::GetDlgItem(hDlg, IDC_PASSWORD);
            lStyle = ::GetWindowLongW(hwndPassword, GWL_STYLE);
            ::SendDlgItemMessageW(hDlg, IDC_PASSWORD, EM_SETPASSWORDCHAR, (ES_PASSWORD & lStyle) ? 0 : (WPARAM)L'*', 0);
            ::InvalidateRect(hwndPassword, nullptr, TRUE);
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

void ParsePassword(__inout_z LPCWSTR pszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin)
{
    size_t i = 0;
    bool fFirstPass = true;
    bool fPasswordIncomplete = true;
    LPCWSTR pszTemp = NULL;

    *ppBin = new unsigned char[cbBin];
    memset(*ppBin, 0, cbBin);

    pszTemp = pszPassword;

    while (fFirstPass || ((*pszTemp) && fPasswordIncomplete))
    {
        if ((*pszTemp) == 0)
        {
            pszTemp = pszPassword;
        }

        *(reinterpret_cast<WCHAR*>(*ppBin + i)) += *pszTemp;
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

// Message handler for password dialog box.
INT_PTR CALLBACK SearchDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    HWND hwndSearchText = nullptr;
    LONG lStyle = 0;
    WCHAR szSearchText[512] = { 0 };
    DWORD dwFirst = 0;
    DWORD dwLast = 0;
    LPWSTR pszText = nullptr;
    LPWSTR pszFind = NULL;

    switch (message)
    {
    case WM_INITDIALOG:
        ::SendDlgItemMessageW(hDlg, IDC_TEXT, EM_LIMITTEXT, ARRAYSIZE(szSearchText) - 1, 0);
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDOK:
        case IDCANCEL:
            ::DestroyWindow(hDlg);
            hSearchDlg = nullptr;
            ::SendMessageW(hText, WM_SETFOCUS, 0, 0);
            return (INT_PTR)TRUE;

        case IDC_NEXT:
            ::GetDlgItemText(hDlg, IDC_TEXT, szSearchText, ARRAYSIZE(szSearchText) - 1);
            ::_wcslwr_s(szSearchText, ARRAYSIZE(szSearchText));
            ::SendMessageW(hText, EM_GETSEL, reinterpret_cast<WPARAM>(&dwFirst), reinterpret_cast<LPARAM>(&dwLast));

            if (dwLast >= 0x100000)
            {
                return (INT_PTR)TRUE;
            }

            pszText = new WCHAR[0x100000];
            ::ZeroMemory(pszText, 0x100000);

            ::GetWindowTextW(hText, pszText, 0x100000);
            ::_wcslwr_s(pszText, 0x100000);

            pszFind = ::wcsstr(pszText + dwLast, szSearchText);
            if (pszFind == NULL)
            {
                return (INT_PTR)TRUE;
            }

            dwFirst = static_cast<DWORD>(pszFind - pszText);
            dwLast = static_cast<DWORD>(dwFirst + ::wcslen(szSearchText));
            ::SendMessageW(hText, EM_SETSEL, dwFirst, dwLast);
            ::SendMessageW(hText, EM_SCROLLCARET, 0, 0);
            delete pszText;
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}


void GenNonce(__inout_bcount(k_cSpmBlockSizeBytes) BYTE* pNonce, __inout_z char * pszHashKey = nullptr)
{
    char szDefaultHashKey[65] = "3BCC8CBF2103DDC295E70BCC305C6BB232479DD2792204A2CA83CE3BEFF9EA43";
    BYTE rgHashKey[4 * sizeof(SPM_WORD)];
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

    // apply one way hash to the noce so we dont leak info in the nonce
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
    ::memcpy(pNonce, pBuf, k_cSpmBlockSizeBytes /2);
    pFbcOneWayHash->Encrypt(pBuf, k_cSpmBlockSizeBytes);
    ::memcpy(pNonce + k_cSpmBlockSizeBytes / 2, pBuf + k_cSpmBlockSizeBytes / 2, k_cSpmBlockSizeBytes / 2);

}

// Apply Nonce will set keys on pCryptor
// use the realy key to encrypt the nonce to create a temporary key for this file
void ApplyNonce(__inout_bcount(k_cSpmBlockSizeBytes) BYTE* pNonce, const unsigned char* pKey, size_t cKey, FBC_CRYPT* pCryptor)
{
    FBC_CRYPT OneWayHash;
    unsigned char rgTemp[k_cSpmBlockSizeBytes] = { 0 };

    ASSERT(cKey == pCryptor->s_GetKeyWidth());

    OneWayHash.SetKeys(pKey, cKey);

    ::memcpy(rgTemp, pNonce, k_cSpmBlockSizeBytes);
    OneWayHash.Encrypt(rgTemp, k_cSpmBlockSizeBytes);

    pCryptor->SetKeys(rgTemp, cKey);
}

void FbcProcessFile(HANDLE hFileIn, HANDLE hFileOut, ULONGLONG cbFileSize, FBC_CRYPT* pCyptor, EFileCryptProcess eFileCryptProcess)
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

void FbcEncryptFile(LPCWSTR pPlaintext, LPCWSTR pCiphertext, const unsigned char* pKey, size_t cbKey)
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
    hFileIn = ::CreateFileW(pPlaintext, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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


    hFileOut = ::CreateFileW(pCiphertext, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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

void FbcDecryptFile(LPCWSTR pCiphertext, LPCWSTR pPlaintext, const unsigned char* pKey, size_t cbKey)
{
    FBC_CRYPT prngCrypt;
    HANDLE hFileIn = NULL;
    HANDLE hFileOut = NULL;
    BOOL fOK = FALSE;
    unsigned char* pNonce = NULL;
    DWORD dwBytes = 0;
    DWORD cbFileSize = 0;


    // open input and output files
    hFileIn = ::CreateFileW(pCiphertext, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFileIn)
    {
        goto Error;
    }

    hFileOut = ::CreateFileW(pPlaintext, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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


void EncryptFile(__in_z LPCWSTR pszFilename, __in_z const LPCWSTR pszPassword)
{
    WCHAR szEncryptedFile[260] = { 0 };       // buffer for encrypted file name
    unsigned char* pKey = new unsigned char[FBC_CRYPT::s_GetKeyWidth()];

    ::ParsePassword(pszPassword, FBC_CRYPT::s_GetKeyWidth(), &pKey);
    ASSERT(FBC_CRYPT::s_ValidKey(pKey, FBC_CRYPT::s_GetKeyWidth()));

    if (FAILED(::StringCchPrintfW(szEncryptedFile, ARRAYSIZE(szEncryptedFile), L"%s.spmbc", pszFilename)))
    {
        goto Error;
    }

    ::FbcEncryptFile(pszFilename, szEncryptedFile, pKey, FBC_CRYPT::s_GetKeyWidth());

    goto Done;

Error:
    ::MessageBoxW(nullptr, L"File name too long", L"Encrypt Failed", MB_OK | MB_ICONERROR);

Done:
    delete[] pKey;
}

void DecryptFile(__in_z LPCWSTR pszFilename, __in_z const LPCWSTR pszPassword)
{
    WCHAR szDecryptedFile[260] = { 0 };       // buffer for encrypted file name
    unsigned char* pKey = new unsigned char[FBC_CRYPT::s_GetKeyWidth()];
    LPWSTR pszExt = NULL;
    
    ::ParsePassword(pszPassword, FBC_CRYPT::s_GetKeyWidth(), &pKey);
    ASSERT(FBC_CRYPT::s_ValidKey(pKey, FBC_CRYPT::s_GetKeyWidth()));

    if (FAILED(::StringCchPrintfW(szDecryptedFile, ARRAYSIZE(szDecryptedFile), L"%s", pszFilename)))
    {
        ::MessageBoxW(nullptr, L"File name too long", L"Decrypt Failed", MB_OK | MB_ICONERROR);
        goto Done;
    }

    pszExt = ::wcsstr(szDecryptedFile, L".spmbc");
    if (NULL == pszExt)
    {
        ::MessageBoxW(nullptr, L"File name must have .spmbc file extension to decrypt", L"Decrypt Failed", MB_OK | MB_ICONERROR);
        goto Done;
    }
    *pszExt = 0;    // truncate extension


    ::FbcDecryptFile(pszFilename, szDecryptedFile, pKey, FBC_CRYPT::s_GetKeyWidth());

Done:
    delete[] pKey;
}

void SaveEncryptedFile(__in_z LPCWSTR pszFilename, __in_z LPCWSTR pszText, __in_z const LPCWSTR pszPassword)
{
    unsigned char* pKey = new unsigned char[FBC_CRYPT::s_GetKeyWidth()];
    FBC_CRYPT* pFbcEncrypt = new FBC_CRYPT();
    int cbText = ::lstrlenW(pszText) * sizeof(*pszText);
    int cBlocks = (cbText / k_cSpmBlockSizeBytes) + 1;
    BYTE* pNonce = new BYTE[k_cSpmBlockSizeBytes];
    unsigned char* pBuffer = new unsigned char[k_cSpmBlockSizeBytes * cBlocks];
    DWORD dwBytesWritten = 0;
    DWORD cbBytesToWrite = 0;
    HANDLE hFileOut = INVALID_HANDLE_VALUE;
    BOOL fOK = FALSE;

    ::ParsePassword(pszPassword, FBC_CRYPT::s_GetKeyWidth(), &pKey);
    ASSERT(FBC_CRYPT::s_ValidKey(pKey, FBC_CRYPT::s_GetKeyWidth()));

    ::ZeroMemory(pBuffer, k_cSpmBlockSizeBytes * cBlocks);
    ::memcpy(pBuffer, reinterpret_cast<const void*>(pszText), cbText);

    ::GenNonce(pNonce);

    ::ApplyNonce(pNonce, pKey, FBC_CRYPT::s_GetKeyWidth(), pFbcEncrypt);

    pFbcEncrypt->Encrypt(pBuffer, k_cSpmBlockSizeBytes * cBlocks);

    hFileOut = ::CreateFileW(pszFilename, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFileOut)
    {
        goto Error;
    }

    fOK = ::WriteFile(hFileOut, pNonce, static_cast<DWORD>(k_cSpmBlockSizeBytes), &dwBytesWritten, NULL);
    if ((!fOK) || (dwBytesWritten != (k_cSpmBlockSizeBytes)))
    {
        goto Error;
    }

    fOK = ::WriteFile(hFileOut, &cbText, static_cast<DWORD>(sizeof(cbText)), &dwBytesWritten, NULL);
    if ((!fOK) || (dwBytesWritten != sizeof(cbText)))
    {
        goto Error;
    }

    fOK = WriteFile(hFileOut, pBuffer, k_cSpmBlockSizeBytes * cBlocks, &dwBytesWritten, NULL);
    if ((!fOK) || (dwBytesWritten != k_cSpmBlockSizeBytes * cBlocks))
    {
        goto Error;
    }

    goto Done;

Error:
    ::MessageBoxW(nullptr, L"Could not write to file", L"Save Failed", MB_OK | MB_ICONERROR);

Done:
    if (hFileOut != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(hFileOut);
    }

    delete pKey;
    delete pNonce;
    delete pFbcEncrypt;
}


void ReadEncryptedFile(__in_z LPCWSTR pszFilename, __in_ecount_z(0x100000) LPWSTR pszText, __in_z const LPCWSTR pszPassword)
{
    unsigned char* pKey = new unsigned char[FBC_CRYPT::s_GetKeyWidth()];
    FBC_CRYPT* pFbcDecrypt = new FBC_CRYPT();
    int cbText = 0;
    int cBlocks = 0;
    BYTE* pNonce = new BYTE[k_cSpmBlockSizeBytes];
    unsigned char* pBuffer = nullptr;
    DWORD dwBytesRead = 0;
    HANDLE hFileIn = INVALID_HANDLE_VALUE;
    BOOL fOK = FALSE;




    hFileIn = ::CreateFile(pszFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFileIn)
    {
        goto Error;
    }

    ::ZeroMemory(pNonce, k_cSpmBlockSizeBytes);
    fOK = ::ReadFile(hFileIn, pNonce, static_cast<DWORD>(k_cSpmBlockSizeBytes), &dwBytesRead, NULL);
    if ((!fOK) || (dwBytesRead != k_cSpmBlockSizeBytes))
    {
        goto Error;
    }

    fOK = ::ReadFile(hFileIn, &cbText, static_cast<DWORD>(sizeof(cbText)), &dwBytesRead, NULL);
    if ((!fOK) || (dwBytesRead != sizeof(cbText)))
    {
        goto Error;
    }
    cBlocks = (cbText / k_cSpmBlockSizeBytes) + 1;
    pBuffer = new unsigned char[k_cSpmBlockSizeBytes * cBlocks +1];
    ::ZeroMemory(pBuffer, k_cSpmBlockSizeBytes * cBlocks);

    fOK = ::ReadFile(hFileIn, pBuffer, k_cSpmBlockSizeBytes * cBlocks, &dwBytesRead, NULL);
    if ((!fOK) || (dwBytesRead != k_cSpmBlockSizeBytes * cBlocks))
    {
        goto Error;
    }


    ::ParsePassword(pszPassword, FBC_CRYPT::s_GetKeyWidth(), &pKey);
    ASSERT(FBC_CRYPT::s_ValidKey(pKey, FBC_CRYPT::s_GetKeyWidth()));

    ::ApplyNonce(pNonce, pKey, FBC_CRYPT::s_GetKeyWidth(), pFbcDecrypt);

    pFbcDecrypt->Decrypt(pBuffer, k_cSpmBlockSizeBytes * cBlocks);

    ::memcpy(reinterpret_cast<void*>(pszText), pBuffer, cbText);
    pszText[cbText / sizeof(*pszText)] = 0;

    goto Done;

Error:
    ::MessageBoxW(nullptr, L"Could not read encrypted data from file", L"Open Failed", MB_OK | MB_ICONERROR);
    pszText[0] = 0;

Done:
    if (hFileIn != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(hFileIn);
    }

    delete pKey;
    delete pNonce;
    delete pFbcDecrypt;
}


//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    LPWINDOWPOS pWp = nullptr;
    OPENFILENAME ofn;        // common dialog box structure
    WCHAR szFile[260] = { 0 };       // buffer for file name
    WCHAR* pszText = nullptr;

    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                ::DialogBoxW(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, AboutDlgProc);
                break;

            case IDM_EXIT:
                ::DestroyWindow(hWnd);
                break;

            case IDM_SEARCH:
                if (hSearchDlg == nullptr)
                {
                    hSearchDlg = ::CreateDialogW(hInst,
                        MAKEINTRESOURCE(IDD_SEARCH),
                        hWnd,
                        (DLGPROC)SearchDlgProc);
                    ::ShowWindow(hSearchDlg, SW_SHOW);
                }
                break;

            case IDM_ENCRYPT:
                // Initialize OPENFILENAME
                ::ZeroMemory(&ofn, sizeof(ofn));
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hWnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile);
                ofn.lpstrFilter = L"All Files\0*.*\0";
                ofn.nFilterIndex = 1;
                ofn.lpstrFileTitle = NULL;
                ofn.nMaxFileTitle = 0;
                ofn.lpstrInitialDir = NULL;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

                // Display the Open dialog box. 
                if (::GetOpenFileNameW(&ofn))
                {
                    if (::DialogBox(hInst, MAKEINTRESOURCE(IDD_PASSWORD), hWnd, PasswordDlgProc) == IDOK)
                    {
                        ::EncryptFile(ofn.lpstrFile, szPassword);
                    }
                }

                break;

            case IDM_DECRYPT:
                // Initialize OPENFILENAME
                ::ZeroMemory(&ofn, sizeof(ofn));
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hWnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile);
                ofn.lpstrFilter = L"SPM encrypted file (*.spmbc)\0*.spmbc\0";
                ofn.nFilterIndex = 1;
                ofn.lpstrFileTitle = NULL;
                ofn.nMaxFileTitle = 0;
                ofn.lpstrInitialDir = NULL;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

                // Display the Open dialog box. 
                if (::GetOpenFileNameW(&ofn))
                {
                    if (::DialogBox(hInst, MAKEINTRESOURCE(IDD_PASSWORD), hWnd, PasswordDlgProc) == IDOK)
                    {
                        ::DecryptFile(ofn.lpstrFile, szPassword);
                    }
                }

                break;

            case IDM_OPEN:
                // Initialize OPENFILENAME
                ::ZeroMemory(&ofn, sizeof(ofn));
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hWnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile);
                ofn.lpstrFilter = L"SPM encrypted text (*.spmbc)\0*.spmbc\0All Files\0*.*\0";
                ofn.nFilterIndex = 1;
                ofn.lpstrFileTitle = NULL;
                ofn.nMaxFileTitle = 0;
                ofn.lpstrInitialDir = NULL;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

                // Display the Open dialog box. 
                if (::GetOpenFileNameW(&ofn))
                {
                    if (::DialogBox(hInst, MAKEINTRESOURCE(IDD_PASSWORD), hWnd, PasswordDlgProc) == IDOK)
                    {
                        pszText = new WCHAR[0x100000];
                        ::ZeroMemory(pszText, 0x100000);

                        ::ReadEncryptedFile(ofn.lpstrFile, pszText, szPassword);
                        ::SetWindowTextW(hText, pszText);

                        delete [] pszText;

                    }
                }

                break;

            case IDM_SAVE:
                // Initialize OPENFILENAME
                ::ZeroMemory(&ofn, sizeof(ofn));
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hWnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile);
                ofn.lpstrFilter = L"SPM encrypted text (*.spmbc)\0*.spmbc\0All Files\0*.*\0";
                ofn.nFilterIndex = 1;
                ofn.lpstrFileTitle = NULL;
                ofn.nMaxFileTitle = 0;
                ofn.lpstrInitialDir = NULL;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_CREATEPROMPT | OFN_OVERWRITEPROMPT;

                if (::DialogBoxW(hInst, MAKEINTRESOURCE(IDD_PASSWORD), hWnd, PasswordDlgProc) == IDOK)
                {
                    if (::GetSaveFileNameW(&ofn))
                    {
                        pszText = new WCHAR[0x100000];
                        ::ZeroMemory(pszText, 0x100000);

                        ::GetWindowTextW(hText, pszText, 0x100000);
                        ::SaveEncryptedFile(ofn.lpstrFile, pszText, szPassword);

                        delete [] pszText;
                    }
                }
                break;

            default:
                return ::DefWindowProcW(hWnd, message, wParam, lParam);
            }
        }
        break;

    case WM_CREATE:
        hText = ::CreateWindowW(L"EDIT",
            0,
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_WANTRETURN | ES_AUTOVSCROLL | WS_VSCROLL | ES_NOHIDESEL,
            3, 0,
            1, 1,
            hWnd,
            (HMENU)IDC_TEXT,
            ::GetModuleHandle(NULL),
            NULL);

        ::PostMessageW(hText, EM_LIMITTEXT, 0xFFFFF, 0);
        break;

    case WM_WINDOWPOSCHANGED:
        pWp = reinterpret_cast<LPWINDOWPOS>(lParam);
        ::SetWindowPos(hText, HWND_TOP, 3, 0, pWp->cx - 18, pWp->cy - 60, SWP_NOMOVE | SWP_NOZORDER);
        break;

    case WM_DESTROY:
        ::PostQuitMessage(0);
        break;

    default:
        return ::DefWindowProcW(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            ::EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

