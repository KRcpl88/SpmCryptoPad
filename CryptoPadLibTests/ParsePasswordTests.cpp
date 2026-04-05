#include "CppUnitTest.h"
#include "../CryptoPadLib/CryptoPadUtils.h"
#include "../CryptoPadLib/SpmBlockCipher64.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CryptoPadLibTests
{
    TEST_CLASS(ParsePasswordTests)
    {
    public:

        TEST_METHOD(TestParsePasswordOutputIsCorrectSize)
        {
            size_t cbKey = CSpmBlockCipher64::s_GetKeyWidth();
            unsigned char* pKey = nullptr;

            ParsePassword(L"P@s$w0rd!", cbKey, &pKey);

            Assert::IsNotNull(pKey, L"ParsePassword should allocate a key buffer");
            delete[] pKey;
        }

        TEST_METHOD(TestParsePasswordOutputIsNonZero)
        {
            size_t cbKey = CSpmBlockCipher64::s_GetKeyWidth();
            unsigned char* pKey = nullptr;

            ParsePassword(L"P@s$w0rd!", cbKey, &pKey);

            bool fAllZero = true;
            for (size_t i = 0; i < cbKey; i++)
            {
                if (pKey[i] != 0)
                {
                    fAllZero = false;
                    break;
                }
            }
            delete[] pKey;

            Assert::IsFalse(fAllZero, L"ParsePassword should produce non-zero output for a non-empty password");
        }

        TEST_METHOD(TestParsePasswordSamePasswordProducesSameKey)
        {
            size_t cbKey = CSpmBlockCipher64::s_GetKeyWidth();
            unsigned char* pKey1 = nullptr;
            unsigned char* pKey2 = nullptr;

            ParsePassword(L"P@s$w0rd!", cbKey, &pKey1);
            ParsePassword(L"P@s$w0rd!", cbKey, &pKey2);

            bool fEqual = (::memcmp(pKey1, pKey2, cbKey) == 0);

            Assert::IsTrue(fEqual, L"Same password should always produce the same key");

            size_t cbExpectedKey = 0;
            unsigned char* pExpectedKey = NULL;
            char rgExpectedKeyHex[] =
                "5000400073002400770030007200640021005000400073002400770030007200";

            HexToBin(rgExpectedKeyHex, 1, &cbExpectedKey, &pExpectedKey);
            Assert::IsTrue(cbExpectedKey == cbKey, L"Key should be correct width");

            fEqual = (::memcmp(pKey1, pExpectedKey, cbExpectedKey) == 0);
            Assert::IsTrue(fEqual, L"Same password should always produce the same key");

            delete[] pKey1;
            delete[] pKey2;
        }

        TEST_METHOD(TestParsePasswordDifferentPasswordsProduceDifferentKeys)
        {
            size_t cbKey = CSpmBlockCipher64::s_GetKeyWidth();
            unsigned char* pKey1 = nullptr;
            unsigned char* pKey2 = nullptr;

            ParsePassword(L"P@s$w0rd!", cbKey, &pKey1);
            ParsePassword(L"Different!", cbKey, &pKey2);

            bool fEqual = (::memcmp(pKey1, pKey2, cbKey) == 0);

            Assert::IsFalse(fEqual, L"Different passwords should produce different keys");

            delete[] pKey1;
            delete[] pKey2;
        }

    };
}
