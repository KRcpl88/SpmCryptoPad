#include "CppUnitTest.h"
#include "../CryptoPadLib/SpmBlockCipher64.h"
#include "../CryptoPadLib/CryptoPadUtils.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CryptoPadLibTests
{
    static const char* const k_pszDefaultPassword = "P@s$w0rd!";

    // Helper: set up a cipher instance with a password-derived key (defaults to k_pszDefaultPassword)
    static void InitCipher(CSpmBlockCipher64& cipher, __in_z const char* pszPassword = k_pszDefaultPassword)
    {
        size_t cbKey = CSpmBlockCipher64::s_GetKeyWidth();
        unsigned char* pKey = nullptr;
        ParsePasswordA(pszPassword, cbKey, &pKey);
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
        ParsePasswordA(k_pszDefaultPassword, cbKey, &pKey);
        prng.SetKeys(pKey, cbKey);
        delete[] pKey;
    }

    // Test-only derived class to expose protected cipher members
    class CTestCipher : public CSpmBlockCipher64
    {
    public:
        const SPM_SBOX_WORD* GetSbox() const { return m_rgSbox; }
        const SPM_SBOX_WORD* GetReverseSbox() const { return m_rgReverseSbox; }
        SPM_PRNG* GetPrngSBox() { return &m_prngSBox; }
        SPM_PRNG* GetPrngMask() { return &m_prngMask; }
        const unsigned char* GetBlockPermutation() const { return m_rgBlockPermutation; }
    };

    // Helper: convert binary to hex string for test output
    static void BinToHex(__in_bcount(cbData) const unsigned char* rgData, __in size_t cbData, __out_ecount(cbData * 2 + 1) char* pszHex)
    {
        static const char k_szHexDigits[] = "0123456789abcdef";
        for (size_t i = 0; i < cbData; ++i)
        {
            pszHex[i * 2]     = k_szHexDigits[(rgData[i] >> 4) & 0x0F];
            pszHex[i * 2 + 1] = k_szHexDigits[rgData[i] & 0x0F];
        }
        pszHex[cbData * 2] = '\0';
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
            CryptoPadLibTests::InitCipher(cipher2, "Different!");

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
            CryptoPadLibTests::InitCipher(cipherDec, "Different!");
            cipherDec.Decrypt(rgBlock, k_cSpmBlockSizeBytes);

            bool fEqual = (::memcmp(rgBlock, rgOriginal, k_cSpmBlockSizeBytes) == 0);
            Assert::IsFalse(fEqual, L"Decrypting with wrong key should not restore plaintext");
        }

        TEST_METHOD(TestEncryptDecryptTwoBlocksComponentSteps)
        {
            // Same fixed plaintext as TestEncryptDecryptTwoBlocksFixedStaticData
            static const char k_szPlaintext[] =
                "Block 1        |               |               |               |               |               |               |               |"
                "Block 2        |               |               |               |               |               |               |               |";

            const size_t cbData = sizeof(k_szPlaintext) - 1;
            const size_t cBlocks = cbData / k_cSpmBlockSizeBytes;
            unsigned char rgData[cbData] = { 0 };
            ::memcpy(rgData, k_szPlaintext, cbData);

            CryptoPadLibTests::CTestCipher cipherEncManual;
            CryptoPadLibTests::InitCipher(cipherEncManual);

            SPM_PRNG* pPrngMask = cipherEncManual.GetPrngMask();
            SPM_PRNG* pPrngSBox = cipherEncManual.GetPrngSBox();
            const SPM_SBOX_WORD* prgSbox = cipherEncManual.GetSbox();
            const unsigned char* prgBaseBlockPermutation = cipherEncManual.GetBlockPermutation();

            char szActual[k_cSpmBlockSizeBytes * 2 + 1] = { 0 };
            bool fMatch = false;

            // Expected block permutations after shuffle
            static const char k_szEncB0Perm[] =
                "59262e1b13302c5c253c2f2d3124760e1c685302637423646e1a4d083d5d6227"
                "706948327939653e61340b6003383314190d457800730f2b713f495f586f4b6a"
                "3a4f106c055e5204115440427d6b3528464e67097e4401072a512937224a4372"
                "504736664c217a566d1712187b7f0a0c061e5a1657775b7c3b1d4115751f5520";

            static const char k_szEncB1Perm[] =
                "591e226b71667d2f55157045186d3341373d105163446c5c0e475d672e0d6927"
                "0c0749214d53310b240a192d48621d4c3e1608431c011f5f427b14563b752325"
                "7226062c6412293209543a5736523f7a354e000f4f74387c2a6f6a7e02614a20"
                "0446655e286e0340303c05601a34585079171b4b5a776878735b137f11392b76";

            // Expected encrypt intermediate states: [block][round * 3 + substep]
            // substep: 0 = after s_SmForwardPass, 1 = after s_SmReversePass, 2 = after s_ApplyPermutation
            static const char* const k_rgszEncB0[] =
            {
                // Round 0
                "3b2ebb68086f09393dcc861859f7ef1707470f0029ad4dda36e01ef0530cee80"
                "79e5e8eb58279576b2dd9e5fc067c3ccb972bd918bbabdf766408be61e12a998"
                "ebd436ea91f203bced1f75c16baf79824ecf540726e8c728c9c08f3336cb83a2"
                "da266447d5648e0b90dcb3292e745ef00a811df1944b3fe1a5a709611f77d81d",

                "8665ed94e55105b817fd8d66b465b74e25970b6f2c2546e0e5193ccc5dcc0a85"
                "17c1bd166efd5189b9a1224e682eb8f59143ba3c1a01a781f117f912c65cde31"
                "8b696ab6d15dd18b2f5941d5f2a3fa35ee87662dbd3d15ebabe24f941d79c98a"
                "294de1b90a41fad3a94aa1d543f79e98a64378585dbb631a537a78e640d9811d",

                "1a156f688bd1a6ebcc2d9e2298434ea76a2fa1e5f5e6584ad5911994257a43d9"
                "1d411d4665176585354fab810566ed8d51b416b8a1fae1942efd8b53fd5d8917"
                "4178d5c93dbaee4dbdf979de0a3c876929e2d10b5981d35dc6867863b8cc5d12"
                "4eb90a2ce051b96697c131a3b6a9e55c17f18a012540b7bb3c6efa431af2bdf7",

                // Round 1
                "3f7ad16d61adf41be11a97ed8bcaa3d45ea24b89271e649e0366b1cfc3911ba9"
                "8b97c740947bfcf6e1a4e75bad1022338f4641c15e658c38bcefcca5f8528473"
                "c733cf1ba03d5c549d407b9c148d60f04eb3fc5f4d8165823437061366d58a69"
                "8ad688dbac9af95ac50f3ac81c89e9159efa4bcf07a53a19d4af046cd3a14cd1",

                "09338311125e2a33b36fade2284733cedbec80f381a6447457a0eb7e59485c71"
                "5594d44da4a8ac43e953c4066d1a649862b4cf00cbe858c9b973079507b2828c"
                "e86464462aaa595ce09af72b5cd63cff77003a30382204df6b31b2b1d18615e1"
                "e39699327e78a0bc0d6a26a7576b256d0133061a4d342483e37357cce5ab00d1",

                "cb04f36d5c2a01df7e3025c46db4ce5864e0261298cc1a6aa762a011db7333ab"
                "d178d14447b33371ffb26bc92ae283ad5e284d64533c99b11aa8e8e36f594373"
                "f7572b1522cf7796d40786827eeb0064e33159809a00bc4d070906243348aa95"
                "06e95c8174ac323aec948cd6460d57b255b9e1e8a6e5333400a4a057835c386b",

                // Round 2
                "6326630e8224a22e649c6ea9c01c0fcc527989e9314d228157f0e161a0ae8e55"
                "ee014c2aa373041cc4b596139a227e8b815857b35c9715e74fbfebef7c5df054"
                "15decc0d044d3a60206041166169cf65671151ac9b9ddea6bdd096b5649f1fdf"
                "c720ca9ee44d56da4d10e5de7346eceef240714469e54cd2b575990f42b73856",

                "e94b438575f8f04267f764fa25a54978077eecc711252cc8649062248a82d660"
                "d1b2e6789554534d57fc449a50e7c5e3be031db3d4b3b21ef3ba4725dc6be4ae"
                "a3206baf0eea81c69bfddd88ed2eed597ccddf9ef0cc04a73cb385840e2ee185"
                "3f49597c0688b2ca5ddb8f6b0b456a36b885d47de22c73f71e7e211a6dcb2856",

                "d404c750c60eb8a7249e6a44360378b26b9b8f75e31a7ddb6bbe9085077e85cb"
                "56880e2ca5674b6059853c1ef0fa4364f82578c5fced5984e754a31ef78a4dba"
                "dd2188e1cc1d7c49e6472ee40662cd203fb381ecfd28cae2dce9d4734282ea25"
                "9a57d611c8537cdf7eb2ae2eaf5d646bd1f385b3256d492cb395b20bf7edf045",
            };

            static const char* const k_rgszEncB1[] =
            {
                // Round 0
                "75c8befa0ada93706ce5b612fd57fea44aba47d65dfad2a00eaa0d9745c6eb3c"
                "23e8b473b5044e7e22ba9c8794afb968bfcf3f9bd358541b933cdb5e06b8c7af"
                "67f8637ad1b78a32aadea25b1630e777383a95cdef01ce721ae3fb33f7fd888b"
                "85e23d8ef82d03a27d0e2515f00f6fbdd5e07bf01a8cb2293c0393b18292b5f7",

                "62ad7eca60768d13ef8face13b3d86b412fd477162be1ea09a6928a2f32fffbd"
                "0263db1d4e12c29e6fc32819ffe11abedb57d10992bde3548715da4f7805ff20"
                "acb71d86ef1550cd8042f3a3557061af3e8badae06eea2839464663e80eea5db"
                "7e26f74bcae1190a4bbd645c4e48326cc26e9fcb545fd53947f76f951c7349f7",

                "adbd80197e641d63d180c39e022f9aae471c156fda8f576e3b284e9f921aade3"
                "db1d7eff6f20b7bdca5094498619f3134bc2cd86483e5512a273f378bdfddb61"
                "0ab48709bee12669ffdba5cbbe4e8b066c71701242ef4fa3326254f7a0284b54"
                "5ceee162eff776a2d5ff66ca1e3de164ac60ac47ee05f75f39c2af15838d3e95",

                // Round 1
                "da226a300cc91ea014cae86f1c1b658b893f24c8ec916cc3ee8b8fa899045922"
                "3d2cbeb437e28c3ff64db1f51779f523f5878b4458a4eb69824d2082ab7f04cc"
                "8d1140bdb94565ce416a64f8dbca5ba95919b8ad37353c5973829ed3ab5b94aa"
                "e48f4863957e70c0f62a0767bdcd7b7317d490cfe4d98136917e6c8408e2727c",

                "0d2e75e865a1740c670d8b52fafd4eb56c3c25527175bd186f1e865114fdf190"
                "8c22cf7c54c1c21bd4484409f96cee0e671ba3955a459cef67e45a848c6c9f38"
                "c4c52d3737466eb6d29fa15c5a2e5e28ba5aeb5cca0b43ed293fb4eb97a80b44"
                "aee98cf1091ed8776d666b35cb2fdfd60d7c2c8852927fa7d7a02754eacfdc7c",

                "eb4597d8ae6b2d22a3d2481b8cfd6f5c25ea46275a0d1b7cfa44cb2c5aee2e9c"
                "447c759fd438c590096e29dc3709140c6dc2b64e2fba5a6c43cfa18c663c675e"
                "77b567957552e91ef9cf0b880e545acad6522ec19f67845cdf0d52a01886f1ef"
                "35a86c71378ca1517ff1b4e8bdfd1e3f8b65c4d70b6c7c92a70d28e4ed74eb54",

                // Round 2
                "ac2c0a9f5149066138e1d4ffe621165bf10dae7697ca7e620bc5276f5f8e36aa"
                "0cac13a4426e61c54b135753e993d488bc7ee1b253be7b56d4c6d8eaea74c4df"
                "87dd19f1a6f6944cfdc1baf64c2b942b1cfbceb91d1bf687fc7e299f0ae11f8d"
                "9561e8ccc0fd47b13b66a8259728b15d4b90ebdf252aeab2231fa937244752b1",

                "6c13bedc27d486776316a505394a343bdb3771f6eb5d5634225e6875ebe58192"
                "32f0f83fb0381821d657fe1e82822e6d401a41c92275e7cd49e42ac11aa556a7"
                "ca4717a5504f33ab135bcf77f2f503e298b94dde207f698d69ba7fa310ebacd5"
                "b329c79404df7ca9dbdf04218c98b5e4f0925081f231ee5dd6e47a099528b7b1",

                "4d75107cb30417f04113572132e522de71954f7a2a161a9239fe8c50222e13e7"
                "d53fbe56d6a74792043369b7a51eeb77db18ab349898f2db6928cf1adf374003"
                "a93b49c95d05295e82f8ac816db0b920e4f6f5385b63c177b56cf2e4346894cd"
                "21eb82eb50c7d475ee817fdc564adfbaa527cad67fa5b1315df0e2e48d86a309",
            };

            // Pointers to per-block expected data and permutations
            const char* const* rgszEncBlocks[] = { k_rgszEncB0, k_rgszEncB1 };
            const char* rgszEncPerms[] = { k_szEncB0Perm, k_szEncB1Perm };

            // =====================================================================
            // ENCRYPT: manually call component static functions
            // =====================================================================
            for (size_t iBlock = 0; iBlock < cBlocks; ++iBlock)
            {
                unsigned char* pBlock = rgData + iBlock * k_cSpmBlockSizeBytes;
                unsigned char rgPermutationBuffer[k_cSpmBlockSizeBytes] = { 0 };
                unsigned char rgBlockPermutation[k_cSpmBlockSizeBytes] = { 0 };

                // Shuffle block permutation (mirrors s_EncryptBlock Permutation logic)
                ::memcpy(rgBlockPermutation, prgBaseBlockPermutation, k_cSpmBlockSizeBytes);
                for (size_t i = 0; k_cSpmBlockSizeBytes > i; ++i)
                {
                    SPM_SBOX_WORD nTemp = rgBlockPermutation[i];
                    SPM_SBOX_WORD nRand = pPrngSBox->Rand() % k_cSpmBlockSizeBytes;
                    rgBlockPermutation[i] = rgBlockPermutation[nRand];
                    rgBlockPermutation[nRand] = static_cast<unsigned char>(nTemp);
                }

                CryptoPadLibTests::BinToHex(rgBlockPermutation, k_cSpmBlockSizeBytes, szActual);
                fMatch = (::strcmp(szActual, rgszEncPerms[iBlock]) == 0);
                Assert::IsTrue(fMatch, L"Encrypt block permutation shuffle mismatch");

                for (size_t iRound = 0; iRound < 3; ++iRound)
                {
                    size_t iStep = iRound * 3;

                    CSpmBlockCipher64::s_SmForwardPass(pBlock, pPrngMask, prgSbox);
                    CryptoPadLibTests::BinToHex(pBlock, k_cSpmBlockSizeBytes, szActual);
                    fMatch = (::strcmp(szActual, rgszEncBlocks[iBlock][iStep]) == 0);
                    Assert::IsTrue(fMatch, L"Encrypt s_SmForwardPass mismatch");

                    CSpmBlockCipher64::s_SmReversePass(pBlock, pPrngMask, prgSbox);
                    CryptoPadLibTests::BinToHex(pBlock, k_cSpmBlockSizeBytes, szActual);
                    fMatch = (::strcmp(szActual, rgszEncBlocks[iBlock][iStep + 1]) == 0);
                    Assert::IsTrue(fMatch, L"Encrypt s_SmReversePass mismatch");

                    CSpmBlockCipher64::s_ApplyPermutation(pBlock, rgBlockPermutation, rgPermutationBuffer);
                    CryptoPadLibTests::BinToHex(pBlock, k_cSpmBlockSizeBytes, szActual);
                    fMatch = (::strcmp(szActual, rgszEncBlocks[iBlock][iStep + 2]) == 0);
                    Assert::IsTrue(fMatch, L"Encrypt s_ApplyPermutation mismatch");
                }
            }

            // Verify manual encrypt matches known ciphertext from TestEncryptDecryptTwoBlocksFixedStaticData
            CryptoPadLibTests::CTestCipher cipherEncRef;
            CryptoPadLibTests::InitCipher(cipherEncRef);
            unsigned char rgDataRef[cbData] = { 0 };
            ::memcpy(rgDataRef, k_szPlaintext, cbData);
            cipherEncRef.Encrypt(rgDataRef, cbData);
            fMatch = (::memcmp(rgData, rgDataRef, cbData) == 0);
            Assert::IsTrue(fMatch, L"Manual component encrypt should match cipher.Encrypt");

            // =====================================================================
            // DECRYPT: manually call component static functions
            // =====================================================================
            CryptoPadLibTests::CTestCipher cipherDecManual;
            CryptoPadLibTests::InitCipher(cipherDecManual);

            SPM_PRNG* pPrngMaskDec = cipherDecManual.GetPrngMask();
            SPM_PRNG* pPrngSBoxDec = cipherDecManual.GetPrngSBox();
            const SPM_SBOX_WORD* prgReverseSbox = cipherDecManual.GetReverseSbox();
            const unsigned char* prgBaseBlockPermDec = cipherDecManual.GetBlockPermutation();

            // Expected s_ReverseSmForwardPass intermediate states (differ from encrypt FWD values
            // because the forward/reverse pass boundary overlaps at byte k_cSpmBlockInflectionIndex-1)
            static const char* const k_rgszDecRfwdB0[] =
            {
                // Round 2
                "6326630e8224a22e649c6ea9c01c0fcc527989e9314d228157f0e161a0ae8e55"
                "ee014c2aa373041cc4b596139a227e8b815857b35c9715e74fbfebef7c5df054"
                "15decc0d044d3a60206041166169cf65671151ac9b9ddea6bdd096b5649f1fdf"
                "c720ca9ee44d56da4d10e5de7346eceef240714469e54cd2b575990f42b75e6b",

                // Round 1
                "3f7ad16d61adf41be11a97ed8bcaa3d45ea24b89271e649e0366b1cfc3911ba9"
                "8b97c740947bfcf6e1a4e75bad1022338f4641c15e658c38bcefcca5f8528473"
                "c733cf1ba03d5c549d407b9c148d60f04eb3fc5f4d8165823437061366d58a69"
                "8ad688dbac9af95ac50f3ac81c89e9159efa4bcf07a53a19d4af046cd3a122f7",

                // Round 0
                "3b2ebb68086f09393dcc861859f7ef1707470f0029ad4dda36e01ef0530cee80"
                "79e5e8eb58279576b2dd9e5fc067c3ccb972bd918bbabdf766408be61e12a998"
                "ebd436ea91f203bced1f75c16baf79824ecf540726e8c728c9c08f3336cb83a2"
                "da266447d5648e0b90dcb3292e745ef00a811df1944b3fe1a5a709611f777f7c",
            };

            static const char* const k_rgszDecRfwdB1[] =
            {
                // Round 2
                "ac2c0a9f5149066138e1d4ffe621165bf10dae7697ca7e620bc5276f5f8e36aa"
                "0cac13a4426e61c54b135753e993d488bc7ee1b253be7b56d4c6d8eaea74c4df"
                "87dd19f1a6f6944cfdc1baf64c2b942b1cfbceb91d1bf687fc7e299f0ae11f8d"
                "9561e8ccc0fd47b13b66a8259728b15d4b90ebdf252aeab2231fa93724472054",

                // Round 1
                "da226a300cc91ea014cae86f1c1b658b893f24c8ec916cc3ee8b8fa899045922"
                "3d2cbeb437e28c3ff64db1f51779f523f5878b4458a4eb69824d2082ab7f04cc"
                "8d1140bdb94565ce416a64f8dbca5ba95919b8ad37353c5973829ed3ab5b94aa"
                "e48f4863957e70c0f62a0767bdcd7b7317d490cfe4d98136917e6c8408e25195",

                // Round 0
                "75c8befa0ada93706ce5b612fd57fea44aba47d65dfad2a00eaa0d9745c6eb3c"
                "23e8b473b5044e7e22ba9c8794afb968bfcf3f9bd358541b933cdb5e06b8c7af"
                "67f8637ad1b78a32aadea25b1630e777383a95cdef01ce721ae3fb33f7fd888b"
                "85e23d8ef82d03a27d0e2515f00f6fbdd5e07bf01a8cb2293c0393b18292de7c",
            };

            const char* const* rgszDecRfwd[] = { k_rgszDecRfwdB0, k_rgszDecRfwdB1 };

            // Plaintext blocks in hex for final round 0 verification
            static const char k_szPlaintextB0Hex[] =
                "426c6f636b203120202020202020207c2020202020202020202020202020207c"
                "2020202020202020202020202020207c2020202020202020202020202020207c"
                "2020202020202020202020202020207c2020202020202020202020202020207c"
                "2020202020202020202020202020207c2020202020202020202020202020207c";

            static const char k_szPlaintextB1Hex[] =
                "426c6f636b203220202020202020207c2020202020202020202020202020207c"
                "2020202020202020202020202020207c2020202020202020202020202020207c"
                "2020202020202020202020202020207c2020202020202020202020202020207c"
                "2020202020202020202020202020207c2020202020202020202020202020207c";

            const char* rgszPlaintextHex[] = { k_szPlaintextB0Hex, k_szPlaintextB1Hex };

            for (size_t iBlock = 0; iBlock < cBlocks; ++iBlock)
            {
                unsigned char* pBlock = rgData + iBlock * k_cSpmBlockSizeBytes;
                unsigned char rgPermutationBuffer[k_cSpmBlockSizeBytes] = { 0 };
                unsigned char rgBlockPermutation[k_cSpmBlockSizeBytes] = { 0 };
                unsigned char rgReverseBlockPermutation[k_cSpmBlockSizeBytes] = { 0 };

                // Shuffle block permutation (same shuffle as encrypt yields same permutation)
                ::memcpy(rgBlockPermutation, prgBaseBlockPermDec, k_cSpmBlockSizeBytes);
                for (size_t i = 0; k_cSpmBlockSizeBytes > i; ++i)
                {
                    SPM_SBOX_WORD nTemp = rgBlockPermutation[i];
                    SPM_SBOX_WORD nRand = pPrngSBoxDec->Rand() % k_cSpmBlockSizeBytes;
                    rgBlockPermutation[i] = rgBlockPermutation[nRand];
                    rgBlockPermutation[nRand] = static_cast<unsigned char>(nTemp);
                }

                CryptoPadLibTests::BinToHex(rgBlockPermutation, k_cSpmBlockSizeBytes, szActual);
                fMatch = (::strcmp(szActual, rgszEncPerms[iBlock]) == 0);
                Assert::IsTrue(fMatch, L"Decrypt block permutation should match encrypt permutation");

                // Build reverse permutation
                for (size_t i = 0; k_cSpmBlockSizeBytes > i; ++i)
                {
                    rgReverseBlockPermutation[rgBlockPermutation[i]] = static_cast<unsigned char>(i);
                }

                // Pre-fill all decrypt masks for this block
                const size_t cMasks = 6 * k_cSpmBlockInflectionIndex - 3;
                SPM_SBOX_WORD rgMask[cMasks] = { 0 };
                CSpmBlockCipher64::s_FillDecryptMasks(rgMask, pPrngMaskDec);

                size_t l = cMasks;

                // Decrypt rounds in reverse order (2, 1, 0)
                for (size_t jj = 0; jj < 3; ++jj)
                {
                    size_t iRound = 2 - jj;
                    size_t iEncStep = iRound * 3;

                    // s_ApplyPermutation (reverse): undoes encrypt's s_ApplyPermutation
                    // Expected result matches encrypt state after s_SmReversePass of same round
                    CSpmBlockCipher64::s_ApplyPermutation(pBlock, rgReverseBlockPermutation, rgPermutationBuffer);
                    CryptoPadLibTests::BinToHex(pBlock, k_cSpmBlockSizeBytes, szActual);
                    fMatch = (::strcmp(szActual, rgszEncBlocks[iBlock][iEncStep + 1]) == 0);
                    Assert::IsTrue(fMatch, L"Decrypt s_ApplyPermutation (reverse) mismatch");

                    // s_ReverseSmForwardPass: partially undoes the encrypt round's substitution passes
                    CSpmBlockCipher64::s_ReverseSmForwardPass(pBlock, prgReverseSbox, rgMask, &l);
                    CryptoPadLibTests::BinToHex(pBlock, k_cSpmBlockSizeBytes, szActual);
                    fMatch = (::strcmp(szActual, rgszDecRfwd[iBlock][jj]) == 0);
                    Assert::IsTrue(fMatch, L"Decrypt s_ReverseSmForwardPass mismatch");

                    // s_ReverseSmReversePass: completes undoing the encrypt round
                    // Expected result matches encrypt state after s_ApplyPermutation of the previous
                    // round, or the original plaintext for round 0
                    CSpmBlockCipher64::s_ReverseSmReversePass(pBlock, prgReverseSbox, rgMask, &l);
                    CryptoPadLibTests::BinToHex(pBlock, k_cSpmBlockSizeBytes, szActual);
                    if (iRound > 0)
                    {
                        fMatch = (::strcmp(szActual, rgszEncBlocks[iBlock][(iRound - 1) * 3 + 2]) == 0);
                        Assert::IsTrue(fMatch, L"Decrypt s_ReverseSmReversePass mismatch");
                    }
                    else
                    {
                        fMatch = (::strcmp(szActual, rgszPlaintextHex[iBlock]) == 0);
                        Assert::IsTrue(fMatch, L"Decrypt final s_ReverseSmReversePass should restore plaintext block");
                    }
                }
            }

            // Final verification: decrypted data matches original plaintext
            fMatch = (::memcmp(rgData, k_szPlaintext, cbData) == 0);
            Assert::IsTrue(fMatch, L"Manual component decrypt should restore original plaintext");
        }
    };
}
