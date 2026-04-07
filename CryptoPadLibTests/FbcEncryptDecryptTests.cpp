#include "CppUnitTest.h"
#include "../CryptoPadLib/CryptoPadUtils.h"
#include <strsafe.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CryptoPadLibTests
{
    extern const LPCSTR g_pszTestPassword;

    TEST_CLASS(FbcEncryptDecryptTests)
    {
    public:

        TEST_METHOD(TestFbcEncryptDecryptRoundTrip)
        {
            WCHAR szTempDir[MAX_PATH] = { 0 };
            WCHAR szPlaintext[MAX_PATH] = { 0 };
            WCHAR szCiphertext[MAX_PATH] = { 0 };
            WCHAR szDecrypted[MAX_PATH] = { 0 };
            HANDLE hFile = INVALID_HANDLE_VALUE;
            DWORD dwBytes = 0;
            unsigned char* pKey = nullptr;
            size_t cbKey = 0;
            bool fContentsMatch = false;

            const char rgOriginal[] = "Hello, CryptoPad!";
            const size_t cbOriginal = sizeof(rgOriginal) - 1;
            char rgDecrypted[64] = { 0 };

            // Build temp file paths
            ::GetTempPathW(MAX_PATH, szTempDir);
            ::GetTempFileNameW(szTempDir, L"fbc", 0, szPlaintext);
            ::StringCchPrintfW(szCiphertext, MAX_PATH, L"%s.spmbc", szPlaintext);
            ::StringCchPrintfW(szDecrypted, MAX_PATH, L"%s.dec", szPlaintext);

            // Write plaintext file
            hFile = ::CreateFileW(szPlaintext, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            Assert::AreNotEqual((void*)INVALID_HANDLE_VALUE, (void*)hFile, L"Failed to create plaintext temp file");
            ::WriteFile(hFile, rgOriginal, static_cast<DWORD>(cbOriginal), &dwBytes, NULL);
            ::CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;

            // Derive key from password
            cbKey = FBC_CRYPT::s_GetKeyWidth();
            ParsePasswordA(g_pszTestPassword, cbKey, &pKey);

            // Encrypt
            ::FbcEncryptFile(szPlaintext, szCiphertext, pKey, cbKey);

            // Decrypt
            ::FbcDecryptFile(szCiphertext, szDecrypted, pKey, cbKey);

            // Read decrypted file
            hFile = ::CreateFileW(szDecrypted, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            Assert::AreNotEqual((void*)INVALID_HANDLE_VALUE, (void*)hFile, L"Failed to open decrypted temp file");
            ::ReadFile(hFile, rgDecrypted, static_cast<DWORD>(cbOriginal), &dwBytes, NULL);
            ::CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;

            // Verify size and contents before cleanup
            bool fSizeMatch = (dwBytes == cbOriginal);
            fContentsMatch = fSizeMatch && (::memcmp(rgOriginal, rgDecrypted, cbOriginal) == 0);

            // Cleanup temp files
            delete[] pKey;
            ::DeleteFileW(szPlaintext);
            ::DeleteFileW(szCiphertext);
            ::DeleteFileW(szDecrypted);

            Assert::IsTrue(fSizeMatch, L"Decrypted file size should match original plaintext size");
            Assert::IsTrue(fContentsMatch, L"Decrypted content should match original plaintext");
        }

    };
}
