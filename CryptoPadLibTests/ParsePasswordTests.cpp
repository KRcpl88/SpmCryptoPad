#include "CppUnitTest.h"
#include "TestConstants.h"
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

            ParsePassword(g_pwszDefaultPassword, cbKey, &pKey);

            Assert::IsNotNull(pKey, L"ParsePassword should allocate a key buffer");
            delete[] pKey;
        }

        TEST_METHOD(TestParsePasswordOutputIsNonZero)
        {
            size_t cbKey = CSpmBlockCipher64::s_GetKeyWidth();
            unsigned char* pKey = nullptr;

            ParsePassword(g_pwszDefaultPassword, cbKey, &pKey);

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

            ParsePassword(g_pwszDefaultPassword, cbKey, &pKey1);
            ParsePassword(g_pwszDefaultPassword, cbKey, &pKey2);

            bool fEqual = (::memcmp(pKey1, pKey2, cbKey) == 0);
            delete[] pKey1;
            delete[] pKey2;

            Assert::IsTrue(fEqual, L"Same password should always produce the same key");
        }

        TEST_METHOD(TestParsePasswordDifferentPasswordsProduceDifferentKeys)
        {
            size_t cbKey = CSpmBlockCipher64::s_GetKeyWidth();
            unsigned char* pKey1 = nullptr;
            unsigned char* pKey2 = nullptr;

            ParsePassword(g_pwszDefaultPassword, cbKey, &pKey1);
            ParsePassword(L"Different!", cbKey, &pKey2);

            bool fEqual = (::memcmp(pKey1, pKey2, cbKey) == 0);
            delete[] pKey1;
            delete[] pKey2;

            Assert::IsFalse(fEqual, L"Different passwords should produce different keys");
        }

    };
}
