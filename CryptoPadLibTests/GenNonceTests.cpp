#include "CppUnitTest.h"
#include "../CryptoPadLib/CryptoPadUtils.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CryptoPadLibTests
{
	TEST_CLASS(GenNonceTests)
	{
	public:
		
        TEST_METHOD(TestGenNonceOutputNotAllZeros)
        {
            BYTE nonce[k_cSpmBlockSizeBytes] = { 0 };

            GenNonce(nonce);

            bool allZero = true;
            for (size_t i = 0; i < k_cSpmBlockSizeBytes; i++)
            {
                if (nonce[i] != 0)
                {
                    allZero = false;
                    break;
                }
            }
            Assert::IsFalse(allZero, L"GenNonce should produce non-zero output");
        }

        TEST_METHOD(TestGenNonceTwoCallsProduceDifferentResults)
        {
            BYTE nonce1[k_cSpmBlockSizeBytes] = { 0 };
            BYTE nonce2[k_cSpmBlockSizeBytes] = { 0 };

            GenNonce(nonce1);
            GenNonce(nonce2);

            bool noncesAreEqual = (memcmp(nonce1, nonce2, k_cSpmBlockSizeBytes) == 0);
            Assert::IsFalse(noncesAreEqual, L"Two consecutive calls to GenNonce should produce different results");
        }

        TEST_METHOD(TestGenNonceWithCustomHashKey)
        {
            BYTE nonce[k_cSpmBlockSizeBytes] = { 0 };
            char customKey[] = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";

            GenNonce(nonce, customKey);

            bool allZero = true;
            for (size_t i = 0; i < k_cSpmBlockSizeBytes; i++)
            {
                if (nonce[i] != 0)
                {
                    allZero = false;
                    break;
                }
            }
            Assert::IsFalse(allZero, L"GenNonce with custom hash key should produce non-zero output");
        }

        TEST_METHOD(TestGenNonceDefaultAndCustomHashKeyProduceDifferentResults)
        {
            BYTE nonce1[k_cSpmBlockSizeBytes] = { 0 };
            BYTE nonce2[k_cSpmBlockSizeBytes] = { 0 };
            char customKey[] = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";

            GenNonce(nonce1);
            GenNonce(nonce2, customKey);

            bool noncesAreEqual = (memcmp(nonce1, nonce2, k_cSpmBlockSizeBytes) == 0);
            Assert::IsFalse(noncesAreEqual, L"GenNonce with default and custom hash key should produce different results");
        }

	};
}
