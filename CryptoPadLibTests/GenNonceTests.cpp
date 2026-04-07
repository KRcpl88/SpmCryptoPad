#include "CppUnitTest.h"
#include "../CryptoPadLib/CryptoPadUtils.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CryptoPadLibTests
{
    const LPCSTR g_pszTestPassword = "P@s$w0rd!";

    TEST_MODULE_INITIALIZE(ModuleInitialize)
    {
        size_t cKey = 0;
        unsigned char* pKey = NULL;
        char rgKey[] = "b6a4c072764a2233db9c23b0bc79c143";

        HexToBin(rgKey, 1, &cKey, &pKey);

        FBC_CRYPT::s_ConstructCodebook(CSpmBlockCipher64::BLOCK_MODE::Permutation);

        FBC_CRYPT::s_PermuteCodebook(16, pKey, cKey);
        delete[] pKey;

        FBC_CRYPT::s_CheckCodebook();
    }

	TEST_CLASS(GenNonceTests)
	{
	public:
		
        TEST_METHOD(TestGenNonceOutputNotAllZeros)
        {
            BYTE rgNonce[k_cSpmBlockSizeBytes] = { 0 };

            ::GenNonce(rgNonce);

            bool fAllZero = true;
            for (size_t i = 0; i < k_cSpmBlockSizeBytes; i++)
            {
                if (rgNonce[i] != 0)
                {
                    fAllZero = false;
                    break;
                }
            }
            Assert::IsFalse(fAllZero, L"GenNonce should produce non-zero output");
        }

        TEST_METHOD(TestGenNonceTwoCallsProduceDifferentResults)
        {
            BYTE rgNonce1[k_cSpmBlockSizeBytes] = { 0 };
            BYTE rgNonce2[k_cSpmBlockSizeBytes] = { 0 };

            ::GenNonce(rgNonce1);
            ::GenNonce(rgNonce2);

            bool fNoncesAreEqual = (::memcmp(rgNonce1, rgNonce2, k_cSpmBlockSizeBytes) == 0);
            Assert::IsFalse(fNoncesAreEqual, L"Two consecutive calls to GenNonce should produce different results");
        }

        TEST_METHOD(TestGenNonceWithCustomHashKey)
        {
            BYTE rgNonce[k_cSpmBlockSizeBytes] = { 0 };
            char rgCustomKey[] = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";

            ::GenNonce(rgNonce, rgCustomKey);

            bool fAllZero = true;
            for (size_t i = 0; i < k_cSpmBlockSizeBytes; i++)
            {
                if (rgNonce[i] != 0)
                {
                    fAllZero = false;
                    break;
                }
            }
            Assert::IsFalse(fAllZero, L"GenNonce with custom hash key should produce non-zero output");
        }

        TEST_METHOD(TestGenNonceDefaultAndCustomHashKeyProduceDifferentResults)
        {
            BYTE rgNonce1[k_cSpmBlockSizeBytes] = { 0 };
            BYTE rgNonce2[k_cSpmBlockSizeBytes] = { 0 };
            char rgCustomKey[] = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";

            ::GenNonce(rgNonce1);
            ::GenNonce(rgNonce2, rgCustomKey);

            bool fNoncesAreEqual = (::memcmp(rgNonce1, rgNonce2, k_cSpmBlockSizeBytes) == 0);
            Assert::IsFalse(fNoncesAreEqual, L"GenNonce with default and custom hash key should produce different results");
        }

	};
}
