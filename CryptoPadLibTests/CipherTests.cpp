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
                "3d65962f36523e98649efe005a57d5d80376374f8f2600923d98d9c5766ab9ce"
                "dc40bd3045654a17a4ebab25071a23279b21906ebdee4b001bd21c20a64f8364"
                "7eda8ee25ebbc89cdea630ccbd4ddc0bec3a9c1de8517efddf48c9612baa6ad7"
                "844f27adf06a132a4dc63897f72dd1ecf0d12bdfae9985474f9cbdad0c4f0297"
                "60c2b2bc25ef562ff8ff489173086beda3b13d3d145b67df84cce111be730c00"
                "008ef5f37017a4576547586f08f4de8fac9c8ae1421247378854acbba90d0c12"
                "684d517f5c769dec6f260bc162aa84ea46ddb0e6340512e1e1231cc841c73772"
                "164d73af893d3b842e27e2e8650d8af14f2c7aa0b93a3a33e4ffcc25c42a4cd2";

            HexToBin(rgExpectedDataHex, 1, &cbExpectedData, &pExpectedData);

            CryptoPadLibTests::InitCipher(cipherEnc);
            CryptoPadLibTests::InitCipher(cipherDec);

            // Verify PRNG state of cipherEnc after InitCipher
            SPM_WORD rgStateEnc[6] = { 0 };
            cipherEnc.GetPrngState(rgStateEnc);
            Assert::AreEqual(static_cast<SPM_WORD>(0x2FC1CF3A7257322F), rgStateEnc[0], L"cipherEnc SBox State mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x7230772473405021), rgStateEnc[1], L"cipherEnc SBox Key mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(4), rgStateEnc[2], L"cipherEnc SBox Idx mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x3077247340502164), rgStateEnc[3], L"cipherEnc Mask State mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x7724734050216473), rgStateEnc[4], L"cipherEnc Mask Key mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0), rgStateEnc[5], L"cipherEnc Mask Idx mismatch");

            // Verify PRNG state of cipherDec after InitCipher (should match cipherEnc)
            SPM_WORD rgStateDec[6] = { 0 };
            cipherDec.GetPrngState(rgStateDec);
            Assert::AreEqual(static_cast<SPM_WORD>(0x2FC1CF3A7257322F), rgStateDec[0], L"cipherDec SBox State mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x7230772473405021), rgStateDec[1], L"cipherDec SBox Key mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(4), rgStateDec[2], L"cipherDec SBox Idx mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x3077247340502164), rgStateDec[3], L"cipherDec Mask State mismatch");
            Assert::AreEqual(static_cast<SPM_WORD>(0x7724734050216473), rgStateDec[4], L"cipherDec Mask Key mismatch");
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
                "722a235128132f4d7d080e2d4a7e204f5d582c145b0005500b4447733d484c0c"
                "123c6f5a1c177c2b335c663e6c64635443365f6b563f320f1f24795746776d4e"
                "3571417a256a596570753b7b031a151934017f162168533927181b060d076e1e"
                "787460623a09024922043026760a401d29674231454b37526155105e2e691138";

            static const char k_szEncB1Perm[] =
                "66061e331b045524355418750857347a3258375e60744d4e41382d442161395d"
                "633e760547534248720e100b3f13701219506b112765221d253a6e2b430f4f45"
                "303d735b09024a235a6c790c4c647c6f003146563c7f2c71671a7d0117072051"
                "6236402e7b0d77034b2f5f591f296a6952165c2a4914263b6d287e7815681c0a";

            // Expected encrypt intermediate states: [block][round * 3 + substep]
            // substep: 0 = after s_SmForwardPass, 1 = after s_SmReversePass, 2 = after s_ApplyPermutation
            static const char* const k_rgszEncB0[] =
            {
                // Round 0
                "b88bfcdd33cec4799c6729d36cf6c0c14f80f18db0821008aac2ad7eb696a3ec"
                "c420a06790c89cdab8c2f0fec5d35769799eaee07e9c1ddb48943182c2bfaa3f"
                "06fad0132681f426a5e92f1a73c0bfd92ba094b3e91f2c0b9cf05d7b687b3217"
                "319ff5aa3e1af8eb6cfb64b3814ad397bd16c53aed05294e4fd6032da194c948",

                "283838bf54881fa969eafdfb367d37fc665256a6461f5c431e9237f7231a78d2"
                "b5c4652d11cf64c18f7e642c1e5cc43fa9b588d061290ce080952b83fa87d6b0"
                "0d41d1a254941bc2219e8a82b9a1163d5d6ec8662b0d4da2b8e57d0747139241"
                "9573ec756cfb1d0b397961303df04f7527b2a8afc17fd933a0ccdf3aad67b648",

                "1f6e1db9795c0713eafbf01ed247fde0dfb6b588a61666cfe53da17d11754180"
                "372b3938955430b8542738c156fbad1f61af0c8f5d0db5d948a26c8ac4232c29"
                "4fd1a8a992c1fa371a0b367f78a9b0fc43bf334d3fcc6183521b2d467e663a88"
                "eca075c45cc264b20d6794d01ed69265214128f7739e3d87952ba28264697dc8",

                // Round 1
                "c544fd4f5682e3e07b6d879f9b39fbab023de73c09ba9e5d4479cbd9f37d5b91"
                "1b507d20198dbbc2b280f1b38bede3c76ff63e0b878858025c2dd90c39a629b0"
                "0015cc2738bf8508e7dd7abd7a571565eb746c13ef78cef1c3d71c34963b371f"
                "9dd6a39a6e65a651113b91c47e2f19eaae37f1fb505577cb00b170afe230bb3f",

                "3e9ac16aed5714a7cd0cbfa932bd4cb859fe70db2f788538312163759a6e3a32"
                "d6e578fb9d44e4e5626b4d799bc3c4b22f02b3f369f76a7481ee334afc79b816"
                "7ae5871e306b572c13dddfe6035915e23d2849de1ee0ebb9239df3645f23042c"
                "9882b6d8019242f30f586bd06e1545be0b6bc74062a32384f02759ba24c5193f",

                "78284203588564230c921531325fbf745919d657db15de449de259f39dbe2c81"
                "4c1e0fc1ee30d023ed0b9ae570a924146b406a623d7a02233fb901dfe59a79f7"
                "4587c72f2162fc636ef332a33aa716b8386a84ebb227694afe57fb2f6b59bab3"
                "b6f0d8c4c32c4d6be0c56bf39bb8047813e53e7582dd6e7998331ee6e4cdbd49",

                // Round 2
                "0cc2d918700db7e17218ac0fa6e214dde3f67e0be4b100c5a5284dcb4fb33bd0"
                "fba2dcf09dd566d866ff90e879d1b2a9431bcddaf7e6754c35a02cb2f57768fb"
                "68a57a1ffb79dcc03a1110c1bed1dd302522ab92a5be6f54d7b9b6f59856090c"
                "e1c6c940ada900e46f548b85b39a4f10739a95e8792e75137d11e4a2f99f841b",

                "2bab303aa44f274d4f64d51a3002dc0baadf078f613d52ec005e9cdf4fdebd5a"
                "37a6ecc976920c256e2b1383f7f0ade8e24bd7977e6490d8ce459cfdc8472ddc"
                "eed1dabd6538486af09920ad2fd92698bd659700404d1dd2173dc53e5798d1b9"
                "4fae84271c9e96a6bd369b4a85fe7e6aeb2a8e21bbcc009c4f51036a23c6761b",

                "3d65962f36523e98649efe005a57d5d80376374f8f2600923d98d9c5766ab9ce"
                "dc40bd3045654a17a4ebab25071a23279b21906ebdee4b001bd21c20a64f8364"
                "7eda8ee25ebbc89cdea630ccbd4ddc0bec3a9c1de8517efddf48c9612baa6ad7"
                "844f27adf06a132a4dc63897f72dd1ecf0d12bdfae9985474f9cbdad0c4f0297",
            };

            static const char* const k_rgszEncB1[] =
            {
                // Round 0
                "551954147415ba269e42ccd7d58ce506a62e03ffd6a6d05e2f743be454ae2999"
                "f9204782bdf53aa92e4384029fbe17435670af0c74647503c4bd21b7a5424768"
                "0095e93d30f999954b1d7f242b260bd9db07a99b272146b955e610ea7e603314"
                "1608107b215a307ca5b8ff2156c22a73f706db281071b9874922414f8c9709f3",

                "0a814ffd02ff8541a247325f6bc1aaeeb22404306805f281cf07540dcf0983d1"
                "5349f9fa6abf00cf101796404b72e5422b67a5af5265b215ab2564a926f38c4d"
                "1fb5c2694a2c89e0876f5f3f92f1dc827bc29bb92fa2dde49089b24051e38fa6"
                "b451e258aaa60181d2574d55d460c7f2e9bdc01e1736716df88377b034a5bcf3",

                "7b402c81fffa81e36b4af3403fa617f396af42723634bd51322b8902bc154fd4"
                "8fcfb2e041ab715283601ea9dd5458571fc2b2fdaaa251040783256d2fb5494be"
                "2cf00260d4d9b6acf1789d292f2818c67a6e9bf4785b9c124558769c0d1304d6"
                "809b453f1650a90a5f2c7a56ff86482e5e410c2055ff901b05feeaadcb277a2",

                // Round 1
                "7e2e78107ced389180b86c6f4e6f07e90c477bef84191f8400b53e4e35d24779"
                "1bedbd85b27a5044e5a9887ce20946643cdd0840ac8a03f3c7e39304c966036d"
                "f636e2aaeeb931a2b914216c4acefb370f71ca5c80cd36e096a60a65c17a5874"
                "e1d72702df088550ef4ffe689546c29f238f27656982513c2c76eb452b094b92",

                "d6f79928fec461eda421a99d3064172c3b219bfda5a4bf553569b6e85c74a1b0"
                "e40c640f561bca82551d9f7d2ef268e608b418c94d015fc1e2edd2e53a184ba6"
                "05c8ec6746571bab3a495dff49b2f1e904dc2fa6fb7a8742b9654a84c02aa889"
                "118f25df0a7adcd3005fb5b87afabe18d98e213bca9c72e3bbdd49f0636f6a92",

                "048457d3c40ff72a3046927dff7a1d189fc9e6f29c638ec0a90865fe6ac1997a"
                "a85c5fabede2724dddfa3be587b6df5f05dc3b2817a48f9b69a1ede3fbc80c2e"
                "2535ca3ae8a62f5682ca1b0049bf554bb489d91b2161a66421b83a6721b0fdb5"
                "a57411e4b201d6b96f18be1849bbd2e9684255eca49d64dcf05d2c0af14a497a",

                // Round 2
                "70aa11a7dd9c0dc3ef35d44436faf1c06d5566a2c75216c2d3732312de3ece33"
                "c85cd6bb467dcbf1da1b7cb12b06e6a3df002d3bbda542e762b906a75f095824"
                "95cbf9bd39906d8f03fb6b1255aa5e2cdb11cb8f34e86b87beeeab10dab4ddd3"
                "7a25f419500297cb00bab787680d452526f2b7f632dc467d90000734cbd44748",

                "3b560ce1112505701234843af8e142cc8ae1373716b9aa844d88f45c8e4d54c7"
                "af0c3aefece6516f7a6ba391123d4f3dcc46e8b1573df57317ac8a6f7fedea76"
                "ac0da0c8ffb20bf31c65ff736289c4f1609c9d12a9d2082c84e12ac2df2f00dd"
                "734768de250833bcc18f72230047e227b06741582614a4bb0d654ce45b2ebe48",

                "60c2b2bc25ef562ff8ff489173086beda3b13d3d145b67df84cce111be730c00"
                "008ef5f37017a4576547586f08f4de8fac9c8ae1421247378854acbba90d0c12"
                "684d517f5c769dec6f260bc162aa84ea46ddb0e6340512e1e1231cc841c73772"
                "164d73af893d3b842e27e2e8650d8af14f2c7aa0b93a3a33e4ffcc25c42a4cd2",
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
                "0cc2d918700db7e17218ac0fa6e214dde3f67e0be4b100c5a5284dcb4fb33bd0"
                "fba2dcf09dd566d866ff90e879d1b2a9431bcddaf7e6754c35a02cb2f57768fb"
                "68a57a1ffb79dcc03a1110c1bed1dd302522ab92a5be6f54d7b9b6f59856090c"
                "e1c6c940ada900e46f548b85b39a4f10739a95e8792e75137d11e4a2f99f9c49",

                // Round 1
                "c544fd4f5682e3e07b6d879f9b39fbab023de73c09ba9e5d4479cbd9f37d5b91"
                "1b507d20198dbbc2b280f1b38bede3c76ff63e0b878858025c2dd90c39a629b0"
                "0015cc2738bf8508e7dd7abd7a571565eb746c13ef78cef1c3d71c34963b371f"
                "9dd6a39a6e65a651113b91c47e2f19eaae37f1fb505577cb00b170afe23021c8",

                // Round 0
                "b88bfcdd33cec4799c6729d36cf6c0c14f80f18db0821008aac2ad7eb696a3ec"
                "c420a06790c89cdab8c2f0fec5d35769799eaee07e9c1ddb48943182c2bfaa3f"
                "06fad0132681f426a5e92f1a73c0bfd92ba094b3e91f2c0b9cf05d7b687b3217"
                "319ff5aa3e1af8eb6cfb64b3814ad397bd16c53aed05294e4fd6032da194857c",
            };

            static const char* const k_rgszDecRfwdB1[] =
            {
                // Round 2
                "70aa11a7dd9c0dc3ef35d44436faf1c06d5566a2c75216c2d3732312de3ece33"
                "c85cd6bb467dcbf1da1b7cb12b06e6a3df002d3bbda542e762b906a75f095824"
                "95cbf9bd39906d8f03fb6b1255aa5e2cdb11cb8f34e86b87beeeab10dab4ddd3"
                "7a25f419500297cb00bab787680d452526f2b7f632dc467d90000734cbd4087a",

                // Round 1
                "7e2e78107ced389180b86c6f4e6f07e90c477bef84191f8400b53e4e35d24779"
                "1bedbd85b27a5044e5a9887ce20946643cdd0840ac8a03f3c7e39304c966036d"
                "f636e2aaeeb931a2b914216c4acefb370f71ca5c80cd36e096a60a65c17a5874"
                "e1d72702df088550ef4ffe689546c29f238f27656982513c2c76eb452b0990a2",

                // Round 0
                "551954147415ba269e42ccd7d58ce506a62e03ffd6a6d05e2f743be454ae2999"
                "f9204782bdf53aa92e4384029fbe17435670af0c74647503c4bd21b7a5424768"
                "0095e93d30f999954b1d7f242b260bd9db07a99b272146b955e610ea7e603314"
                "1608107b215a307ca5b8ff2156c22a73f706db281071b9874922414f8c97117c",
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
