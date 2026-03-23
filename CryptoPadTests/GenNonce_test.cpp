#include <gtest/gtest.h>
#include "CryptoPadUtils.h"

static bool IsAllZeros(const BYTE* buf, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        if (buf[i] != 0)
            return false;
    }
    return true;
}

// Test fixture for GenNonce tests.
// Codebook initialisation is handled by CodebookEnvironment in
// SpmBlockCipher64_test.cpp to ensure s_ConstructCodebook is called exactly once.
class GenNonceTest : public ::testing::Test
{
};

// Verify that GenNonce fills the output buffer with non-zero data.
TEST_F(GenNonceTest, OutputIsNotAllZeros)
{
    BYTE nonce[k_cSpmBlockSizeBytes] = { 0 };
    GenNonce(nonce);
    EXPECT_FALSE(IsAllZeros(nonce, k_cSpmBlockSizeBytes))
        << "GenNonce output should not be all zeros";
}

// Verify that two successive calls produce different nonce values.
// A small sleep ensures that the time-based entropy sources advance between calls.
TEST_F(GenNonceTest, TwoCallsProduceDifferentResults)
{
    BYTE nonce1[k_cSpmBlockSizeBytes] = { 0 };
    BYTE nonce2[k_cSpmBlockSizeBytes] = { 0 };

    GenNonce(nonce1);
    Sleep(16); // ensure at least one timer tick advances
    GenNonce(nonce2);

    EXPECT_NE(0, ::memcmp(nonce1, nonce2, k_cSpmBlockSizeBytes))
        << "Two successive GenNonce calls should produce different values";
}

// Verify that GenNonce works when an explicit null hash key is passed.
TEST_F(GenNonceTest, WithNullHashKeyOutputIsNotAllZeros)
{
    BYTE nonce[k_cSpmBlockSizeBytes] = { 0 };
    GenNonce(nonce, nullptr);
    EXPECT_FALSE(IsAllZeros(nonce, k_cSpmBlockSizeBytes))
        << "GenNonce with null hash key should produce non-zero output";
}

// Verify that GenNonce works with a custom hash key.
TEST_F(GenNonceTest, WithCustomHashKeyOutputIsNotAllZeros)
{
    BYTE nonce[k_cSpmBlockSizeBytes] = { 0 };
    char hashKey[65] = "AABB8CBF2103DDC295E70BCC305C6BB232479DD2792204A2CA83CE3BEFF9EA43";
    GenNonce(nonce, hashKey);
    EXPECT_FALSE(IsAllZeros(nonce, k_cSpmBlockSizeBytes))
        << "GenNonce with custom hash key should produce non-zero output";
}
