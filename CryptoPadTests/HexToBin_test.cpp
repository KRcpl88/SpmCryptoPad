#include <gtest/gtest.h>
#include "CryptoPadUtils.h"

// Tests for HexToBin(char* pszHex, size_t cchBin, unsigned char* pBin)
// Note: HexToBin modifies pszHex in-place (it inserts NUL terminators during
// parsing), so each test must use its own mutable copy.

TEST(HexToBinTest, TwoByteEvenHexString)
{
    char hex[] = "0A0B";
    unsigned char bin[2] = { 0 };
    HexToBin(hex, sizeof(bin), bin);
    EXPECT_EQ(0x0A, bin[0]);
    EXPECT_EQ(0x0B, bin[1]);
}

TEST(HexToBinTest, SingleByteHexString)
{
    char hex[] = "FF";
    unsigned char bin[1] = { 0 };
    HexToBin(hex, sizeof(bin), bin);
    EXPECT_EQ(0xFF, bin[0]);
}

TEST(HexToBinTest, UpperCaseHexLetters)
{
    char hex[] = "DEADBEEF";
    unsigned char bin[4] = { 0 };
    HexToBin(hex, sizeof(bin), bin);
    EXPECT_EQ(0xDE, bin[0]);
    EXPECT_EQ(0xAD, bin[1]);
    EXPECT_EQ(0xBE, bin[2]);
    EXPECT_EQ(0xEF, bin[3]);
}

TEST(HexToBinTest, LowerCaseHexLetters)
{
    char hex[] = "deadbeef";
    unsigned char bin[4] = { 0 };
    HexToBin(hex, sizeof(bin), bin);
    EXPECT_EQ(0xDE, bin[0]);
    EXPECT_EQ(0xAD, bin[1]);
    EXPECT_EQ(0xBE, bin[2]);
    EXPECT_EQ(0xEF, bin[3]);
}

TEST(HexToBinTest, OddLengthHexStringPartialFirstByte)
{
    // "A0B" has 3 hex chars -> 2 bytes needed; first byte gets value 0x0A,
    // second byte gets value 0x0B.
    char hex[] = "A0B";
    unsigned char bin[2] = { 0 };
    HexToBin(hex, sizeof(bin), bin);
    EXPECT_EQ(0x0A, bin[0]);
    EXPECT_EQ(0x0B, bin[1]);
}

TEST(HexToBinTest, OutputBufferLargerThanInput_ResultRightAligned)
{
    // "FF" converts to 1 byte; the remaining 3 bytes in the 4-byte buffer
    // should be zeroed.
    char hex[] = "FF";
    unsigned char bin[4] = { 0xCC, 0xCC, 0xCC, 0xCC };
    HexToBin(hex, sizeof(bin), bin);
    EXPECT_EQ(0x00, bin[0]);
    EXPECT_EQ(0x00, bin[1]);
    EXPECT_EQ(0x00, bin[2]);
    EXPECT_EQ(0xFF, bin[3]);
}

// Tests for HexToBin(char* pszHex, size_t nAlign, size_t* pcchBin, unsigned char** ppBin)

TEST(HexToBinAllocTest, ExactAlignmentReturnsCorrectSize)
{
    char hex[] = "0A0B0C0D";  // 4 bytes exactly, nAlign=4
    size_t cchBin = 0;
    unsigned char* pBin = nullptr;
    HexToBin(hex, 4, &cchBin, &pBin);
    EXPECT_EQ(4u, cchBin);
    ASSERT_NE(nullptr, pBin);
    EXPECT_EQ(0x0A, pBin[0]);
    EXPECT_EQ(0x0B, pBin[1]);
    EXPECT_EQ(0x0C, pBin[2]);
    EXPECT_EQ(0x0D, pBin[3]);
    delete[] pBin;
}

TEST(HexToBinAllocTest, UnalignedSizeRoundsUpToAlignment)
{
    // "AABB" -> 2 bytes, nAlign=4 -> rounded up to 4 bytes
    char hex[] = "AABB";
    size_t cchBin = 0;
    unsigned char* pBin = nullptr;
    HexToBin(hex, 4, &cchBin, &pBin);
    EXPECT_EQ(4u, cchBin);
    ASSERT_NE(nullptr, pBin);
    delete[] pBin;
}

TEST(HexToBinAllocTest, AllocatesNonNullBuffer)
{
    char hex[] = "1234";
    size_t cchBin = 0;
    unsigned char* pBin = nullptr;
    HexToBin(hex, 1, &cchBin, &pBin);
    EXPECT_NE(nullptr, pBin);
    delete[] pBin;
}
