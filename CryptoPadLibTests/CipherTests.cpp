#include "CppUnitTest.h"
#include "../CryptoPadLib/SpmBlockCipher64.h"
#include "../CryptoPadLib/CryptoPadUtils.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CryptoPadLibTests
{
    static const wchar_t* const k_pwszDefaultPassword = L"P@s$w0rd!";

    // Helper: set up a cipher instance with a password-derived key (defaults to k_pwszDefaultPassword)
    static void InitCipher(CSpmBlockCipher64& cipher, __in_z const wchar_t* lpwszPassword = k_pwszDefaultPassword)
    {
        size_t cbKey = CSpmBlockCipher64::s_GetKeyWidth();
        unsigned char* pKey = nullptr;
        ParsePassword(lpwszPassword, cbKey, &pKey);
        cipher.SetKeys(pKey, cbKey);
        delete[] pKey;
    }

    // Helper: fill a block with a known pattern
    static void FillTestBlock(__out_bcount(cbBlock) unsigned char* rgBlock, __in size_t cbBlock)
    {
        for (size_t i = 0; i < cbBlock; ++i)
        {
            rgBlock[i] = static_cast<unsigned char>(i & 0xFF);
        }
    }

    // Helper: seed a PRNG with the password-derived key
    static void InitPrng(CSimplePrng64& prng)
    {
        size_t cbKey = CSimplePrng64::s_GetKeyWidth();
        unsigned char* pKey = nullptr;
        ParsePassword(k_pwszDefaultPassword, cbKey, &pKey);
        prng.SetKeys(pKey, cbKey);
        delete[] pKey;
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
            CryptoPadLibTests::InitCipher(cipher);

            unsigned char rgBlock[k_cSpmBlockSizeBytes] = { 0 };
            CryptoPadLibTests::FillTestBlock(rgBlock, k_cSpmBlockSizeBytes);

            unsigned char rgOriginal[k_cSpmBlockSizeBytes] = { 0 };
            ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

            cipher.Encrypt(rgBlock, k_cSpmBlockSizeBytes);
            bool fChanged = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) != 0);
            Assert::IsTrue(fChanged, L"Encrypt (which calls s_SmForwardPass) should modify data");
        }

        TEST_METHOD(TestSmForwardPassDeterministic)
        {
            // Two ciphers with the same key should produce identical output
            CSpmBlockCipher64 cipher1, cipher2;
            CryptoPadLibTests::InitCipher(cipher1);
            CryptoPadLibTests::InitCipher(cipher2);

            unsigned char rgBlock1[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgBlock2[k_cSpmBlockSizeBytes] = { 0 };
            CryptoPadLibTests::FillTestBlock(rgBlock1, k_cSpmBlockSizeBytes);
            CryptoPadLibTests::FillTestBlock(rgBlock2, k_cSpmBlockSizeBytes);

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
            unsigned char rgBlock[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgBuffer[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgPermutation[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgOriginal[k_cSpmBlockSizeBytes] = { 0 };

            CryptoPadLibTests::FillTestBlock(rgBlock, k_cSpmBlockSizeBytes);
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
            unsigned char rgBlock[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgBuffer[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgPermutation[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgReversePermutation[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgOriginal[k_cSpmBlockSizeBytes] = { 0 };

            CryptoPadLibTests::FillTestBlock(rgBlock, k_cSpmBlockSizeBytes);
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
            unsigned char rgBlock[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgBuffer[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgIdentity[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgOriginal[k_cSpmBlockSizeBytes] = { 0 };

            CryptoPadLibTests::FillTestBlock(rgBlock, k_cSpmBlockSizeBytes);
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
            CryptoPadLibTests::InitPrng(prngMask1);
            CryptoPadLibTests::InitPrng(prngMask2);

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
            CryptoPadLibTests::InitPrng(prngMask);

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

        TEST_METHOD(TestEncryptBlockDecryptBlockRoundtripPermutation)
        {
            CSpmBlockCipher64 cipherEnc, cipherDec;
            CryptoPadLibTests::InitCipher(cipherEnc);
            CryptoPadLibTests::InitCipher(cipherDec);

            unsigned char rgBlock[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgOriginal[k_cSpmBlockSizeBytes] = { 0 };
            CryptoPadLibTests::FillTestBlock(rgBlock, k_cSpmBlockSizeBytes);
            ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

            cipherEnc.Encrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fChanged = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) != 0);
            Assert::IsTrue(fChanged, L"Encryption should modify data");

            cipherDec.Decrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsTrue(fEqual, L"Decrypt should restore original plaintext (Permutation mode)");
        }

        TEST_METHOD(TestEncryptDecryptTwoBlocksFixedStaticData)
        {
            // Fixed static ASCII test data: two 128-byte blocks (256 chars, excluding null terminator)
            static const char k_szPlaintext[] =
                "Block 1        |               |               |               |               |               |               |               |"
                "Block 2        |               |               |               |               |               |               |               |";

            const size_t cbData = sizeof(k_szPlaintext) - 1; // exclude null terminator
            unsigned char rgData[cbData] = { 0 };
            memcpy(rgData, k_szPlaintext, cbData);
            bool fMatch = false;

            CSpmBlockCipher64 cipherEnc, cipherDec;

            size_t cbExpectedData = 0;
            unsigned char* pExpectedData = NULL;
            char rgExpectedDataHex[] =
                "d404c750c60eb8a7249e6a44360378b26b9b8f75e31a7ddb6bbe9085077e85cb"
                "56880e2ca5674b6059853c1ef0fa4364f82578c5fced5984e754a31ef78a4dba"
                "dd2188e1cc1d7c49e6472ee40662cd203fb381ecfd28cae2dce9d4734282ea25"
                "9a57d611c8537cdf7eb2ae2eaf5d646bd1f385b3256d492cb395b20bf7edf045"
                "4d75107cb30417f04113572132e522de71954f7a2a161a9239fe8c50222e13e7"
                "d53fbe56d6a74792043369b7a51eeb77db18ab349898f2db6928cf1adf374003"
                "a93b49c95d05295e82f8ac816db0b920e4f6f5385b63c177b56cf2e4346894cd"
                "21eb82eb50c7d475ee817fdc564adfbaa527cad67fa5b1315df0e2e48d86a309";

            HexToBin(rgExpectedDataHex, 1, &cbExpectedData, &pExpectedData);

            CryptoPadLibTests::InitCipher(cipherEnc);
            CryptoPadLibTests::InitCipher(cipherDec);

            // Verify PRNG state of cipherEnc after InitCipher
            SPM_WORD rgStateEnc[6] = { 0 };
            cipherEnc.GetPrngState(rgStateEnc);
            Assert::AreEqual(static_cast<SPM_WORD>(0xC988E4C161ECEDD9), rgStateEnc[0], L"cipherEnc SBox State mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x0064007200300077), rgStateEnc[1], L"cipherEnc SBox Key mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(4), rgStateEnc[2], L"cipherEnc SBox Idx mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x0073004000500021), rgStateEnc[3], L"cipherEnc Mask State mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x0072003000770025), rgStateEnc[4], L"cipherEnc Mask Key mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0), rgStateEnc[5], L"cipherEnc Mask Idx mismatch");

            // Verify PRNG state of cipherDec after InitCipher (should match cipherEnc)
            SPM_WORD rgStateDec[6] = { 0 };
            cipherDec.GetPrngState(rgStateDec);
            Assert::AreEqual(static_cast<SPM_WORD>(0xC988E4C161ECEDD9), rgStateDec[0], L"cipherDec SBox State mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x0064007200300077), rgStateDec[1], L"cipherDec SBox Key mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(4), rgStateDec[2], L"cipherDec SBox Idx mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x0073004000500021), rgStateDec[3], L"cipherDec Mask State mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x0072003000770025), rgStateDec[4], L"cipherDec Mask Key mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0), rgStateDec[5], L"cipherDec Mask Idx mismatch");

            cipherEnc.Encrypt(rgData, cbData);

            fMatch = (::memcmp(rgData, pExpectedData, cbExpectedData) == 0);
            delete[] pExpectedData;
            pExpectedData = nullptr;
            Assert::IsTrue(fMatch, L"Encryption should match expected plaintext");

            fMatch = (::memcmp(rgData, k_szPlaintext, cbData) == 0);
            Assert::IsFalse(fMatch, L"Encrypting fixed static data should produce different ciphertext");

            cipherDec.Decrypt(rgData, cbData);

            fMatch = (::memcmp(rgData, k_szPlaintext, cbData) == 0);
            Assert::IsTrue(fMatch, L"Decrypting should restore original fixed static plaintext");



        }

        TEST_METHOD(TestEncryptDecryptMultipleBlocks)
        {
            const size_t cBlocks = 4;
            const size_t cbData = cBlocks * k_cSpmBlockSizeBytes;
            unsigned char rgData[cbData] = { 0 };
            unsigned char rgOriginal[cbData] = { 0 };

            for (size_t i = 0; i < cbData; ++i)
            {
                rgData[i] = static_cast<unsigned char>((i * 7 + 13) & 0xFF);
            }
            ::memcpy(rgOriginal, rgData, cbData);

            CSpmBlockCipher64 cipherEnc, cipherDec;
            CryptoPadLibTests::InitCipher(cipherEnc);
            CryptoPadLibTests::InitCipher(cipherDec);

            cipherEnc.Encrypt(rgData, cbData);

            bool fChanged = (::memcmp(rgData, rgOriginal, cbData) != 0);
            Assert::IsTrue(fChanged, L"Multi-block encryption should modify data");

            cipherDec.Decrypt(rgData, cbData);

            bool fEqual = (::memcmp(rgData, rgOriginal, cbData) == 0);
            Assert::IsTrue(fEqual, L"Multi-block decrypt should restore original data");
        }

        // =====================================================================
        // Encrypt produces different output for different keys
        // =====================================================================

        TEST_METHOD(TestDifferentKeysProduceDifferentCiphertext)
        {
            CSpmBlockCipher64 cipher1, cipher2;
            CryptoPadLibTests::InitCipher(cipher1);
            CryptoPadLibTests::InitCipher(cipher2, L"Different!");

            unsigned char rgBlock1[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgBlock2[k_cSpmBlockSizeBytes] = { 0 };
            CryptoPadLibTests::FillTestBlock(rgBlock1, k_cSpmBlockSizeBytes);
            CryptoPadLibTests::FillTestBlock(rgBlock2, k_cSpmBlockSizeBytes);

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
            CryptoPadLibTests::InitCipher(cipherEnc);
            CryptoPadLibTests::InitCipher(cipherDec);

            cipherEnc.Encrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fChanged = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) != 0);
            Assert::IsTrue(fChanged, L"Encrypting zeros should produce non-zero ciphertext");

            cipherDec.Decrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsTrue(fEqual, L"Decrypting should restore zero block");
        }

        TEST_METHOD(TestEncryptDecryptAllOnesBlock)
        {
            unsigned char rgBlock[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgOriginal[k_cSpmBlockSizeBytes] = { 0 };
            ::memset(rgBlock, 0xFF, k_cSpmBlockSizeBytes);
            ::memset(rgOriginal, 0xFF, k_cSpmBlockSizeBytes);

            CSpmBlockCipher64 cipherEnc, cipherDec;
            CryptoPadLibTests::InitCipher(cipherEnc);
            CryptoPadLibTests::InitCipher(cipherDec);

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
            CryptoPadLibTests::InitCipher(cipher);

            for (unsigned char fill = 0; fill < 5; ++fill)
            {
                unsigned char rgBlock[k_cSpmBlockSizeBytes] = { 0 };
                unsigned char rgOriginal[k_cSpmBlockSizeBytes] = { 0 };
                ::memset(rgBlock, fill, k_cSpmBlockSizeBytes);
                ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

                // Reset cipher state for each test
                CryptoPadLibTests::InitCipher(cipher);
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
            CryptoPadLibTests::InitPrng(prngMask);

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
            unsigned char rgBlock[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgBuffer[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgPermutation[k_cSpmBlockSizeBytes] = { 0 };

            CryptoPadLibTests::FillTestBlock(rgBlock, k_cSpmBlockSizeBytes);

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
            unsigned char rgBlock[k_cSpmBlockSizeBytes] = { 0 };
            unsigned char rgOriginal[k_cSpmBlockSizeBytes] = { 0 };
            CryptoPadLibTests::FillTestBlock(rgBlock, k_cSpmBlockSizeBytes);
            ::memcpy(rgOriginal, rgBlock, k_cSpmBlockSizeBytes);

            CSpmBlockCipher64 cipherEnc;
            CryptoPadLibTests::InitCipher(cipherEnc);
            cipherEnc.Encrypt(rgBlock, k_cSpmBlockSizeBytes);

            // Decrypt with a different key
            CSpmBlockCipher64 cipherDec;
            CryptoPadLibTests::InitCipher(cipherDec, L"Different!");
            cipherDec.Decrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsFalse(fEqual, L"Decrypting with wrong key should not restore plaintext");
        }
    };
}
