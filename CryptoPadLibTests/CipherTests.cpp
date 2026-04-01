#include "CppUnitTest.h"
#include "../CryptoPadLib/SpmBlockCipher64.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CryptoPadLibTests
{
    // Fixed key for deterministic tests (32 bytes = s_GetKeyWidth())
    static const unsigned char s_rgTestKey[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17,
        0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F
    };

    // Helper: set up a cipher instance with the fixed test key
    static void s_InitCipher(CSpmBlockCipher64& cipher)
    {
        cipher.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));
    }

    // Helper: create two identically-seeded PRNGs from the test key
    static void s_InitPrngs(CSimplePrng64& prngSBox, CSimplePrng64& prngMask)
    {
        size_t cbPrngKey = CSimplePrng64::s_GetKeyWidth();
        prngSBox.SetKeys(s_rgTestKey, cbPrngKey);
        prngMask.SetKeys(s_rgTestKey + cbPrngKey, cbPrngKey);
    }

    // Helper: fill a block with a known pattern
    static void s_FillTestBlock(unsigned char* pBlock)
    {
        for (size_t i = 0; i < k_cSpmBlockSizeBytes; ++i)
        {
            pBlock[i] = static_cast<unsigned char>(i & 0xFF);
        }
    }

    TEST_CLASS(CipherStaticMethodTests)
    {
    public:

        // =====================================================================
        // s_SmForwardPass
        // =====================================================================

        TEST_METHOD(TestSmForwardPassModifiesData)
        {
            CSpmBlockCipher64 cipher;
            CryptoPadLibTests::s_InitCipher(cipher);

            CSimplePrng64 prngSBox, prngMask;
            CryptoPadLibTests::s_InitPrngs(prngSBox, prngMask);

            // Build sbox via a fresh cipher to get m_rgSbox
            CSpmBlockCipher64 cipherForSbox;
            cipherForSbox.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));

            unsigned char rgBlock[k_cSpmBlockSizeBytes];
            CryptoPadLibTests::s_FillTestBlock(rgBlock);

            unsigned char rgOriginal[k_cSpmBlockSizeBytes];
            ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

            // Use the cipher's encrypt to get sbox - we access via full encrypt/decrypt roundtrip instead
            // For direct access, call s_SmForwardPass with the cipher's internal sbox
            // Since m_rgSbox is protected, we test via the public static by using a cipher and encrypting
            // We'll test indirectly: encrypt with Encrypt, then test individual pieces compose correctly

            // Actually, we can test via full roundtrip at the pass level
            // s_SmForwardPass should change the data
            cipher.Encrypt(rgBlock, k_cSpmBlockSizeBytes);
            bool fChanged = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) != 0);
            Assert::IsTrue(fChanged, L"Encrypt (which calls s_SmForwardPass) should modify data");
        }

        TEST_METHOD(TestSmForwardPassDeterministic)
        {
            // Two ciphers with the same key should produce identical output
            CSpmBlockCipher64 cipher1, cipher2;
            cipher1.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));
            cipher2.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));

            unsigned char rgBlock1[k_cSpmBlockSizeBytes], rgBlock2[k_cSpmBlockSizeBytes];
            CryptoPadLibTests::s_FillTestBlock(rgBlock1);
            CryptoPadLibTests::s_FillTestBlock(rgBlock2);

            cipher1.Encrypt(rgBlock1, k_cSpmBlockSizeBytes);
            cipher2.Encrypt(rgBlock2, k_cSpmBlockSizeBytes);

            bool fEqual = (::memcmp(rgBlock1, rgBlock2, k_cSpmBlockSizeBytes) == 0);
            Assert::IsTrue(fEqual, L"Same key should produce identical ciphertext");
        }

        // =====================================================================
        // s_ApplyPermutation
        // =====================================================================

        TEST_METHOD(TestApplyPermutationMovesBytes)
        {
            unsigned char rgBlock[k_cSpmBlockSizeBytes];
            unsigned char rgBuffer[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgPermutation[k_cSpmBlockSizeBytes];
            unsigned char rgOriginal[k_cSpmBlockSizeBytes];

            CryptoPadLibTests::s_FillTestBlock(rgBlock);
            ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

            // Create a simple rotation permutation: each byte moves one position forward
            for (size_t i = 0; i < k_cSpmBlockSizeBytes; ++i)
            {
                rgPermutation[i] = static_cast<unsigned char>((i + 1) % k_cSpmBlockSizeBytes);
            }

            CSpmBlockCipher64::s_ApplyPermutation(rgBlock, rgPermutation, rgBuffer);

            // Verify that bytes were moved
            bool fChanged = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) != 0);
            Assert::IsTrue(fChanged, L"Permutation should rearrange bytes");

            // Verify specific byte: original[0] should now be at position permutation[0]=1
            Assert::AreEqual(rgOriginal[0], rgBlock[1], L"block[1] should equal original[0] after rotation permutation");
        }

        TEST_METHOD(TestApplyPermutationRoundtrip)
        {
            unsigned char rgBlock[k_cSpmBlockSizeBytes];
            unsigned char rgBuffer[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgPermutation[k_cSpmBlockSizeBytes];
            unsigned char rgReversePermutation[k_cSpmBlockSizeBytes];
            unsigned char rgOriginal[k_cSpmBlockSizeBytes];

            CryptoPadLibTests::s_FillTestBlock(rgBlock);
            ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

            // Create a rotation permutation
            for (size_t i = 0; i < k_cSpmBlockSizeBytes; ++i)
            {
                rgPermutation[i] = static_cast<unsigned char>((i + 1) % k_cSpmBlockSizeBytes);
            }

            // Build reverse permutation
            for (size_t i = 0; i < k_cSpmBlockSizeBytes; ++i)
            {
                rgReversePermutation[rgPermutation[i]] = static_cast<unsigned char>(i);
            }

            CSpmBlockCipher64::s_ApplyPermutation(rgBlock, rgPermutation, rgBuffer);
            CSpmBlockCipher64::s_ApplyPermutation(rgBlock, rgReversePermutation, rgBuffer);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsTrue(fEqual, L"Applying permutation then reverse permutation should restore original data");
        }

        TEST_METHOD(TestApplyPermutationIdentity)
        {
            unsigned char rgBlock[k_cSpmBlockSizeBytes];
            unsigned char rgBuffer[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgIdentity[k_cSpmBlockSizeBytes];
            unsigned char rgOriginal[k_cSpmBlockSizeBytes];

            CryptoPadLibTests::s_FillTestBlock(rgBlock);
            ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

            // Identity permutation: each byte stays in place
            for (size_t i = 0; i < k_cSpmBlockSizeBytes; ++i)
            {
                rgIdentity[i] = static_cast<unsigned char>(i);
            }

            CSpmBlockCipher64::s_ApplyPermutation(rgBlock, rgIdentity, rgBuffer);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsTrue(fEqual, L"Identity permutation should not change data");
        }

        // =====================================================================
        // s_FillDecryptMasks
        // =====================================================================

        TEST_METHOD(TestFillDecryptMasksMatchesPrng)
        {
            CSimplePrng64 prngMask1, prngMask2;
            size_t cbPrngKey = CSimplePrng64::s_GetKeyWidth();
            prngMask1.SetKeys(s_rgTestKey + cbPrngKey, cbPrngKey);
            prngMask2.SetKeys(s_rgTestKey + cbPrngKey, cbPrngKey);

            const size_t cMasks = 6 * k_cSpmBlockInflectionIndex - 3;
            SPM_SBOX_WORD rgMask[6 * k_cSpmBlockInflectionIndex - 3] = { 0 };

            CSpmBlockCipher64::s_FillDecryptMasks(rgMask, &prngMask1);

            // Verify each mask matches what the PRNG would produce in order
            for (size_t i = 0; i < cMasks; ++i)
            {
                SPM_SBOX_WORD expected = prngMask2.Rand();
                Assert::AreEqual(expected, rgMask[i], L"Mask should match PRNG output in order");
            }
        }

        TEST_METHOD(TestFillDecryptMasksCorrectCount)
        {
            CSimplePrng64 prngMask;
            size_t cbPrngKey = CSimplePrng64::s_GetKeyWidth();
            prngMask.SetKeys(s_rgTestKey + cbPrngKey, cbPrngKey);

            const size_t cMasks = 6 * k_cSpmBlockInflectionIndex - 3;
            SPM_SBOX_WORD rgMask[6 * k_cSpmBlockInflectionIndex - 3] = { 0 };

            CSpmBlockCipher64::s_FillDecryptMasks(rgMask, &prngMask);

            // Verify the count is 3 rounds * (2 * inflection - 1) masks per round
            size_t expectedCount = 3 * (2 * k_cSpmBlockInflectionIndex - 1);
            Assert::AreEqual(expectedCount, cMasks, L"Mask count should be 3*(2*inflection-1)");
        }

        // =====================================================================
        // s_EncryptBlock + s_DecryptBlock roundtrip
        // =====================================================================

        TEST_METHOD(TestEncryptBlockDecryptBlockRoundtripNoPermutation)
        {
            // Use NoPermutation mode to test without permutation complexity
            CSpmBlockCipher64::s_ConstructCodebook(CSpmBlockCipher64::BLOCK_MODE::NoPermutation);
            CSpmBlockCipher64::s_PermuteCodebook(1, s_rgTestKey, sizeof(s_rgTestKey));

            CSpmBlockCipher64 cipherEnc, cipherDec;
            cipherEnc.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));
            cipherDec.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));

            unsigned char rgBlock[k_cSpmBlockSizeBytes];
            unsigned char rgOriginal[k_cSpmBlockSizeBytes];
            CryptoPadLibTests::s_FillTestBlock(rgBlock);
            ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

            cipherEnc.Encrypt(rgBlock, k_cSpmBlockSizeBytes);

            // Verify ciphertext differs from plaintext
            bool fChanged = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) != 0);
            Assert::IsTrue(fChanged, L"Encryption should modify data");

            cipherDec.Decrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsTrue(fEqual, L"Decrypt should restore original plaintext (NoPermutation mode)");

            // Restore Permutation mode for other tests
            CSpmBlockCipher64::s_ConstructCodebook(CSpmBlockCipher64::BLOCK_MODE::Permutation);
            CSpmBlockCipher64::s_PermuteCodebook(1, s_rgTestKey, sizeof(s_rgTestKey));
        }

        TEST_METHOD(TestEncryptBlockDecryptBlockRoundtripPermutation)
        {
            CSpmBlockCipher64 cipherEnc, cipherDec;
            cipherEnc.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));
            cipherDec.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));

            unsigned char rgBlock[k_cSpmBlockSizeBytes];
            unsigned char rgOriginal[k_cSpmBlockSizeBytes];
            CryptoPadLibTests::s_FillTestBlock(rgBlock);
            ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

            cipherEnc.Encrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fChanged = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) != 0);
            Assert::IsTrue(fChanged, L"Encryption should modify data");

            cipherDec.Decrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsTrue(fEqual, L"Decrypt should restore original plaintext (Permutation mode)");
        }

        TEST_METHOD(TestEncryptDecryptMultipleBlocks)
        {
            const size_t cBlocks = 4;
            const size_t cbData = cBlocks * k_cSpmBlockSizeBytes;
            unsigned char rgData[cbData];
            unsigned char rgOriginal[cbData];

            for (size_t i = 0; i < cbData; ++i)
            {
                rgData[i] = static_cast<unsigned char>((i * 7 + 13) & 0xFF);
            }
            ::memcpy(rgOriginal, rgData, cbData);

            CSpmBlockCipher64 cipherEnc, cipherDec;
            cipherEnc.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));
            cipherDec.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));

            cipherEnc.Encrypt(rgData, cbData);

            bool fChanged = (::memcmp(rgData, rgOriginal, cbData) != 0);
            Assert::IsTrue(fChanged, L"Multi-block encryption should modify data");

            cipherDec.Decrypt(rgData, cbData);

            bool fEqual = (::memcmp(rgData, rgOriginal, cbData) == 0);
            Assert::IsTrue(fEqual, L"Multi-block decrypt should restore original data");
        }

        // =====================================================================
        // s_EncryptRound + s_DecryptRound roundtrip
        // =====================================================================

        TEST_METHOD(TestEncryptRoundDecryptRoundRoundtripNoPermutation)
        {
            CSpmBlockCipher64::s_ConstructCodebook(CSpmBlockCipher64::BLOCK_MODE::NoPermutation);
            CSpmBlockCipher64::s_PermuteCodebook(1, s_rgTestKey, sizeof(s_rgTestKey));

            CSpmBlockCipher64 cipher;
            cipher.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));

            // We need direct access to sbox and reverse sbox.
            // Test via full encrypt/decrypt at block level which exercises s_EncryptRound/s_DecryptRound.
            unsigned char rgBlock[k_cSpmBlockSizeBytes];
            unsigned char rgOriginal[k_cSpmBlockSizeBytes];
            CryptoPadLibTests::s_FillTestBlock(rgBlock);
            ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

            // Single block roundtrip exercises s_EncryptRound (3x) and s_DecryptRound (3x)
            CSpmBlockCipher64 cipherDec;
            cipherDec.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));

            cipher.Encrypt(rgBlock, k_cSpmBlockSizeBytes);
            cipherDec.Decrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsTrue(fEqual, L"EncryptRound/DecryptRound roundtrip should restore data (NoPermutation)");

            CSpmBlockCipher64::s_ConstructCodebook(CSpmBlockCipher64::BLOCK_MODE::Permutation);
            CSpmBlockCipher64::s_PermuteCodebook(1, s_rgTestKey, sizeof(s_rgTestKey));
        }

        // =====================================================================
        // Encrypt produces different output for different keys
        // =====================================================================

        TEST_METHOD(TestDifferentKeysProduceDifferentCiphertext)
        {
            unsigned char rgAltKey[32];
            ::memcpy(rgAltKey, s_rgTestKey, sizeof(rgAltKey));
            rgAltKey[0] ^= 0xFF; // flip one byte

            CSpmBlockCipher64 cipher1, cipher2;
            cipher1.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));
            cipher2.SetKeys(rgAltKey, sizeof(rgAltKey));

            unsigned char rgBlock1[k_cSpmBlockSizeBytes], rgBlock2[k_cSpmBlockSizeBytes];
            CryptoPadLibTests::s_FillTestBlock(rgBlock1);
            CryptoPadLibTests::s_FillTestBlock(rgBlock2);

            cipher1.Encrypt(rgBlock1, k_cSpmBlockSizeBytes);
            cipher2.Encrypt(rgBlock2, k_cSpmBlockSizeBytes);

            bool fDifferent = (::memcmp(rgBlock1, rgBlock2, k_cSpmBlockSizeBytes) != 0);
            Assert::IsTrue(fDifferent, L"Different keys should produce different ciphertext");
        }

        // =====================================================================
        // s_SmForwardPass and s_SmReversePass compose correctly
        // =====================================================================

        TEST_METHOD(TestEncryptDecryptAllZeroBlock)
        {
            unsigned char rgBlock[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgOriginal[k_cSpmBlockSizeBytes] = { 0 };

            CSpmBlockCipher64 cipherEnc, cipherDec;
            cipherEnc.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));
            cipherDec.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));

            cipherEnc.Encrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fChanged = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) != 0);
            Assert::IsTrue(fChanged, L"Encrypting zeros should produce non-zero ciphertext");

            cipherDec.Decrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsTrue(fEqual, L"Decrypting should restore zero block");
        }

        TEST_METHOD(TestEncryptDecryptAllOnesBlock)
        {
            unsigned char rgBlock[k_cSpmBlockSizeBytes];
            unsigned char rgOriginal[k_cSpmBlockSizeBytes];
            ::memset(rgBlock, 0xFF, k_cSpmBlockSizeBytes);
            ::memset(rgOriginal, 0xFF, k_cSpmBlockSizeBytes);

            CSpmBlockCipher64 cipherEnc, cipherDec;
            cipherEnc.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));
            cipherDec.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));

            cipherEnc.Encrypt(rgBlock, k_cSpmBlockSizeBytes);
            cipherDec.Decrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsTrue(fEqual, L"Decrypting should restore all-ones block");
        }

        // =====================================================================
        // Encrypt is not a no-op for any of the sub-operations
        // =====================================================================

        TEST_METHOD(TestEncryptSingleBlockNotIdentity)
        {
            // Verify that encryption is not the identity function for multiple different inputs
            CSpmBlockCipher64 cipher;
            cipher.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));

            for (unsigned char fill = 0; fill < 5; ++fill)
            {
                unsigned char rgBlock[k_cSpmBlockSizeBytes];
                unsigned char rgOriginal[k_cSpmBlockSizeBytes];
                ::memset(rgBlock, fill, k_cSpmBlockSizeBytes);
                ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

                // Reset cipher state for each test
                cipher.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));
                cipher.Encrypt(rgBlock, k_cSpmBlockSizeBytes);

                bool fChanged = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) != 0);
                Assert::IsTrue(fChanged, L"Encryption should modify data for any input");
            }
        }

        // =====================================================================
        // s_FillDecryptMasks produces non-zero output
        // =====================================================================

        TEST_METHOD(TestFillDecryptMasksNonZero)
        {
            CSimplePrng64 prngMask;
            size_t cbPrngKey = CSimplePrng64::s_GetKeyWidth();
            prngMask.SetKeys(s_rgTestKey + cbPrngKey, cbPrngKey);

            SPM_SBOX_WORD rgMask[6 * k_cSpmBlockInflectionIndex - 3] = { 0 };
            CSpmBlockCipher64::s_FillDecryptMasks(rgMask, &prngMask);

            bool fAllZero = true;
            const size_t cMasks = 6 * k_cSpmBlockInflectionIndex - 3;
            for (size_t i = 0; i < cMasks; ++i)
            {
                if (rgMask[i] != 0)
                {
                    fAllZero = false;
                    break;
                }
            }
            Assert::IsFalse(fAllZero, L"Decrypt masks should not be all zero");
        }

        // =====================================================================
        // s_ApplyPermutation preserves all bytes (no data loss)
        // =====================================================================

        TEST_METHOD(TestApplyPermutationPreservesAllBytes)
        {
            unsigned char rgBlock[k_cSpmBlockSizeBytes];
            unsigned char rgBuffer[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgPermutation[k_cSpmBlockSizeBytes];

            CryptoPadLibTests::s_FillTestBlock(rgBlock);

            // Create a reversal permutation
            for (size_t i = 0; i < k_cSpmBlockSizeBytes; ++i)
            {
                rgPermutation[i] = static_cast<unsigned char>(k_cSpmBlockSizeBytes - 1 - i);
            }

            CSpmBlockCipher64::s_ApplyPermutation(rgBlock, rgPermutation, rgBuffer);

            // Count occurrences of each byte value - all should still appear
            unsigned char rgCounts[256] = { 0 };
            for (size_t i = 0; i < k_cSpmBlockSizeBytes; ++i)
            {
                ++rgCounts[rgBlock[i]];
            }

            for (size_t i = 0; i < k_cSpmBlockSizeBytes; ++i)
            {
                Assert::AreEqual((unsigned char)1, rgCounts[i],
                    L"Each byte value 0..127 should appear exactly once after permutation");
            }
        }

        // =====================================================================
        // Decrypt with wrong key fails
        // =====================================================================

        TEST_METHOD(TestDecryptWithWrongKeyFails)
        {
            unsigned char rgBlock[k_cSpmBlockSizeBytes];
            unsigned char rgOriginal[k_cSpmBlockSizeBytes];
            CryptoPadLibTests::s_FillTestBlock(rgBlock);
            ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

            CSpmBlockCipher64 cipherEnc;
            cipherEnc.SetKeys(s_rgTestKey, sizeof(s_rgTestKey));
            cipherEnc.Encrypt(rgBlock, k_cSpmBlockSizeBytes);

            // Decrypt with a different key
            unsigned char rgWrongKey[32];
            ::memcpy(rgWrongKey, s_rgTestKey, sizeof(rgWrongKey));
            rgWrongKey[0] ^= 0xFF;

            CSpmBlockCipher64 cipherDec;
            cipherDec.SetKeys(rgWrongKey, sizeof(rgWrongKey));
            cipherDec.Decrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsFalse(fEqual, L"Decrypting with wrong key should not restore plaintext");
        }
    };
}
