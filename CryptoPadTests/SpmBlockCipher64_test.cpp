#include <gtest/gtest.h>
#include "SpmBlockCipher64.h"

// s_ConstructCodebook contains a Debug ASSERT that fires if it is called more
// than once in the same process (it expects each entry to be 0 before writing).
// A GlobalTestEnvironment is therefore used to call s_ConstructCodebook exactly
// once, before any test suite's SetUpTestSuite runs. GenNonceTest relies on
// this environment instead of calling s_ConstructCodebook itself.

class CodebookEnvironment : public ::testing::Environment
{
public:
    void SetUp() override
    {
        FBC_CRYPT::s_ConstructCodebook(CSpmBlockCipher64::BLOCK_MODE::Permutation);
    }
};

// AddGlobalTestEnvironment takes ownership; SetUp runs before all tests.
static ::testing::Environment* const g_pCodebookEnv =
    ::testing::AddGlobalTestEnvironment(new CodebookEnvironment());

// After s_ConstructCodebook(Permutation), the S-box codebook must be the
// identity mapping: s_rgCodebook[i] == i for every i in [0, SPM_SBOX_WIDTH).
TEST(ConstructCodebookTest, CodebookIsIdentity)
{
    for (size_t i = 0; i < SPM_SBOX_WIDTH; ++i)
    {
        ASSERT_EQ(static_cast<SPM_SBOX_WORD>(i), FBC_CRYPT::s_rgCodebook[i])
            << "s_rgCodebook[" << i << "] should equal " << i;
    }
}

// After s_ConstructCodebook(Permutation), the permutation codebook pointer
// must be non-null.
TEST(ConstructCodebookTest, Permutation_PermutationCodebookIsNotNull)
{
    EXPECT_NE(nullptr, FBC_CRYPT::s_prgPermutationCodebook);
}

// After s_ConstructCodebook(Permutation), the permutation codebook must be
// the identity mapping: s_prgPermutationCodebook[i] == i for every
// i in [0, k_cSpmBlockSizeBytes).
TEST(ConstructCodebookTest, Permutation_PermutationCodebookIsIdentity)
{
    ASSERT_NE(nullptr, FBC_CRYPT::s_prgPermutationCodebook);
    for (size_t i = 0; i < k_cSpmBlockSizeBytes; ++i)
    {
        EXPECT_EQ(static_cast<unsigned char>(i), FBC_CRYPT::s_prgPermutationCodebook[i])
            << "s_prgPermutationCodebook[" << i << "] should equal " << i;
    }
}
