// CryptoPad.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "CryptoPad.h"
#include "../CryptoPadLib/SpmBlockCipher64.h"
#include "../CryptoPadLib/CryptoPadUtils.h"

#define MAX_LOADSTRING 100


// Global Variables:
HINSTANCE hInst;                                // current instance
HWND hText;                                     // text control
HWND hSearchDlg = nullptr;                      // find dialog
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
WCHAR szPassword[1024] = { 0 };
bool fAsciiPassword = true;

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                Run(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    AboutDlgProc(HWND, UINT, WPARAM, LPARAM);
void                EncryptFile(__in_z LPCWSTR pwszFilename, __in_z LPCWSTR pwszPassword);
void                DecryptFile(__in_z LPCWSTR pwszFilename, __in_z LPCWSTR pwszPassword);


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

static bool IsHexStringW(__in_z LPCWSTR pwszArg, __in size_t cchExpected)
{
    if (::wcslen(pwszArg) != cchExpected)
    {
        return false;
    }
    for (size_t i = 0; i < cchExpected; ++i)
    {
        WCHAR wc = pwszArg[i];
        if (!((wc >= L'0' && wc <= L'9') || (wc >= L'a' && wc <= L'f') || (wc >= L'A' && wc <= L'F')))
        {
            return false;
        }
    }
    return true;
}


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    int cArgs = 0;
    LPWSTR* rgArgs = nullptr;
    char szCodebook[33] = "b6a4c072764a2233db9c23b0bc79c143";
    char szArgCodebook[33] = { 0 };
    bool fHeadless = false;

    // Initialize global strings
    ::LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    ::LoadStringW(hInstance, IDS_CRYPTOPAD, szWindowClass, MAX_LOADSTRING);
    ::MyRegisterClass(hInstance);

    rgArgs = ::CommandLineToArgvW(::GetCommandLineW(), &cArgs);

    if (rgArgs != nullptr && cArgs >= 2)
    {
        switch (rgArgs[1][0])
        {
        case L'E':
        case L'e':
            if (cArgs < 4)
            {
                ::MessageBoxW(nullptr, L"Usage: CryptoPad.exe E <filename> <password> [<codebook>]", L"Argument Error", MB_OK | MB_ICONERROR);
                ::LocalFree(rgArgs);
                return 1;
            }
            fHeadless = true;
            if (cArgs >= 5 && IsHexStringW(rgArgs[4], 32))
            {
                if (::WideCharToMultiByte(CP_UTF8, 0, rgArgs[4], -1, szArgCodebook, ARRAYSIZE(szArgCodebook), nullptr, nullptr) != 33)
                {
                    ::MessageBoxW(nullptr, L"Invalid codebook argument", L"Argument Error", MB_OK | MB_ICONERROR);
                    ::LocalFree(rgArgs);
                    return 1;
                }
                ::InitCodebook(szArgCodebook);
            }
            else
            {
                ::InitCodebook(szCodebook);
            }
            ::EncryptFile(rgArgs[2], rgArgs[3]);
            break;

        case L'D':
        case L'd':
            if (cArgs < 4)
            {
                ::MessageBoxW(nullptr, L"Usage: CryptoPad.exe D <filename> <password> [<codebook>]", L"Argument Error", MB_OK | MB_ICONERROR);
                ::LocalFree(rgArgs);
                return 1;
            }
            fHeadless = true;
            if (cArgs >= 5 && IsHexStringW(rgArgs[4], 32))
            {
                if (::WideCharToMultiByte(CP_UTF8, 0, rgArgs[4], -1, szArgCodebook, ARRAYSIZE(szArgCodebook), nullptr, nullptr) != 33)
                {
                    ::MessageBoxW(nullptr, L"Invalid codebook argument", L"Argument Error", MB_OK | MB_ICONERROR);
                    ::LocalFree(rgArgs);
                    return 1;
                }
                ::InitCodebook(szArgCodebook);
            }
            else
            {
                ::InitCodebook(szCodebook);
            }
            ::DecryptFile(rgArgs[2], rgArgs[3]);
            break;

        default:
            ::LocalFree(rgArgs);
            return 1;
        }
    }
    else
    {
        ::InitCodebook(szCodebook);
    }

    if (rgArgs != nullptr)
    {
        ::LocalFree(rgArgs);
    }

    if (fHeadless)
    {
        return 0;
    }

    return ::Run(hInstance, nCmdShow);
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex = { 0 };

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
    hInst = hInstance; // Store instance handle in our global variable

    HWND hWnd = ::CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

    if (!hWnd)
    {
        return FALSE;
    }

    ::ShowWindow(hWnd, nCmdShow);
    ::UpdateWindow(hWnd);

    HACCEL hAccelTable = ::LoadAcceleratorsW(hInstance, MAKEINTRESOURCE(IDC_CRYPTOPAD));

    MSG msg = { 0 };

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
        ::CheckDlgButton(hDlg, IDC_ASCII_PASSWORD, fAsciiPassword ? BST_CHECKED : BST_UNCHECKED);
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDOK:
            ::GetDlgItemText(hDlg, IDC_PASSWORD, szPassword, ARRAYSIZE(szPassword) - 1);
            fAsciiPassword = (::IsDlgButtonChecked(hDlg, IDC_ASCII_PASSWORD) == BST_CHECKED);
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


void ParsePasswordDispatch(__in_z LPCWSTR pwszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin)
{
    char szPwdA[ARRAYSIZE(szPassword)] = { 0 };
    if (fAsciiPassword)
    {
        ::WideCharToMultiByte(CP_UTF8, 0, pwszPassword, -1, szPwdA, ARRAYSIZE(szPwdA), nullptr, nullptr);
        ::ParsePasswordA(szPwdA, cbBin, ppBin);
    }
    else
    {
        ::ParsePasswordW(pwszPassword, cbBin, ppBin);
    }
}

void EncryptFile(__in_z LPCWSTR pszFilename, __in_z const LPCWSTR pszPassword)
{
    WCHAR szEncryptedFile[260] = { 0 };       // buffer for encrypted file name
    unsigned char* pKey = new unsigned char[FBC_CRYPT::s_GetKeyWidth()];

    ParsePasswordDispatch(pszPassword, FBC_CRYPT::s_GetKeyWidth(), &pKey);
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
    
    ParsePasswordDispatch(pszPassword, FBC_CRYPT::s_GetKeyWidth(), &pKey);
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

    ParsePasswordDispatch(pszPassword, FBC_CRYPT::s_GetKeyWidth(), &pKey);
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


    ParsePasswordDispatch(pszPassword, FBC_CRYPT::s_GetKeyWidth(), &pKey);
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
    OPENFILENAME ofn = { 0 };        // common dialog box structure
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

