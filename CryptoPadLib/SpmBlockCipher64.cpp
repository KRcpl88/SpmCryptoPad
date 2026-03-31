#include "../CryptoPad/framework.h"
#include "SpmBlockCipher64.h"



CSimplePrng64::CSimplePrng64() : m_wState(0), m_wKey(0), m_idx(0)
{
}

void CSimplePrng64::SetKeys(__in_ecount(cKeyData) const unsigned char* pKeyData, size_t cbKeyData)
{
    ASSERT(cbKeyData <= s_GetKeyWidth())

    m_idx = 0;
    m_wState = reinterpret_cast<const SPM_WORD *>(pKeyData)[0];
    m_wKey = reinterpret_cast<const SPM_WORD *>(pKeyData)[1];
    m_wKey |= 1;  // make sure it is odd
}



CSpmBlockCipher64::BLOCK_MODE CSpmBlockCipher64::s_eBlockMode = CSpmBlockCipher64::BLOCK_MODE::NoPermutation;
SPM_SBOX_WORD CSpmBlockCipher64::s_rgCodebook[SPM_SBOX_WIDTH] = { 0 };
unsigned char* CSpmBlockCipher64::s_prgPermutationCodebook;

void CSpmBlockCipher64::s_ConstructCodebook(CSpmBlockCipher64::BLOCK_MODE eBlockMode)
{
    size_t i;
    // initialize Sbox values to 0, 1, 2, ... N
    for (i = 0; ARRAYSIZE(s_rgCodebook) > i; ++i)
    {
        ASSERT (s_rgCodebook[i] == 0)

        s_rgCodebook[i] = static_cast<SPM_SBOX_WORD>(i);
    }

    s_eBlockMode = eBlockMode;
    if (eBlockMode == BLOCK_MODE::NoPermutation)
    {
        return;
    }

    if (s_prgPermutationCodebook != NULL)
    {
        delete[] s_prgPermutationCodebook;
        s_prgPermutationCodebook = NULL;
    }

    s_prgPermutationCodebook = new unsigned char[k_cSpmBlockSizeBytes];
    ::memset(s_prgPermutationCodebook, 0, k_cSpmBlockSizeBytes);

    // initialize permutation values to 0, 1, 2, ... N
    for (i = 0; k_cSpmBlockSizeBytes > i; ++i)
    {
        ASSERT (s_prgPermutationCodebook[i] == 0)

        s_prgPermutationCodebook[i] = static_cast<unsigned char>(i);
    }
}

void CSpmBlockCipher64::s_CheckCodebook()
{
    size_t i;
    UCHAR rgCount[SPM_SBOX_WIDTH];

    ::memset(rgCount, 0, sizeof(rgCount));

    for (i = 0; ARRAYSIZE(s_rgCodebook) > i; ++i)
    {
        ++(rgCount[s_rgCodebook[i]]);
        ASSERT (rgCount[s_rgCodebook[i]] <= 1)
    }

    if (s_prgPermutationCodebook == NULL)
    {
        return;
    }

    ::memset(rgCount, 0, sizeof(rgCount));

    C_ASSERT(ARRAYSIZE(rgCount) >= k_cSpmBlockSizeBytes);

    for (i = 0; k_cSpmBlockSizeBytes > i; ++i)
    {
        ++(rgCount[s_prgPermutationCodebook[i]]);
        ASSERT(rgCount[s_prgPermutationCodebook[i]] <= 1)
    }
}

void CSpmBlockCipher64::s_PermuteCodebook(int n, __in_ecount(cKeyData) const unsigned char* pKeyData, size_t cKeyData)
{
    SPM_SBOX_WORD nRand;
    SPM_SBOX_WORD nTemp;
    SPM_PRNG prngPermutor;
    size_t j;
    int i;

    prngPermutor.SetKeys(pKeyData, cKeyData);

    for (i = 0; n > i; ++i)
    {
        for (j = 0; ARRAYSIZE(s_rgCodebook) > j; ++j)
        {
            // remember the current value for this Sbox entry
            nTemp = s_rgCodebook[j];
            nRand = prngPermutor.Rand();

            // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
            s_rgCodebook[j] = s_rgCodebook[nRand];
            s_rgCodebook[nRand] = nTemp;
        }
    }

    if (s_prgPermutationCodebook == NULL)
    {
        return;
    }

    for (i = 0; n > i; ++i)
    {
        for (j = 0; k_cSpmBlockSizeBytes > j; ++j)
        {
            // remember the current value for this Sbox entry
            nTemp = s_prgPermutationCodebook[j];
            nRand = prngPermutor.Rand() % k_cSpmBlockSizeBytes;

            // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
            s_prgPermutationCodebook[j] = s_prgPermutationCodebook[nRand];
            s_prgPermutationCodebook[nRand] = static_cast<unsigned char>(nTemp);
        }
    }
}


void CSpmBlockCipher64::InitSbox()
{
    // math is specific to 64 bit version
    C_ASSERT(sizeof(size_t) == sizeof(INT64));

    // initialize Sbox values from codebook
    ::memcpy(m_rgSbox, s_rgCodebook, sizeof(m_rgSbox));

    if (s_eBlockMode == BLOCK_MODE::NoPermutation)
    {
        return;
    }

    ASSERT(s_prgPermutationCodebook != NULL);
    ASSERT(k_cSpmBlockSizeBytes == sizeof(m_rgBlockPermutation));
    ::memcpy(m_rgBlockPermutation, s_prgPermutationCodebook, sizeof(m_rgBlockPermutation));
}

void CSpmBlockCipher64::PermuteSbox()
{
    SPM_SBOX_WORD nRand;
    SPM_SBOX_WORD nTemp;
    size_t i=0;

    size_t j=0;
    for(j=0; 16 >j; ++j)
    {
        for(i=0; ARRAYSIZE(m_rgSbox) >i; ++i)
        {
            // remember the current value for this Sbox entry
            nTemp = m_rgSbox[i];
            nRand = m_prngSBox.Rand();

            // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
            m_rgSbox[i] = m_rgSbox[static_cast<SPM_SBOX_WORD>( nRand)];
            m_rgSbox[static_cast<SPM_SBOX_WORD>(nRand)] = nTemp;
        }
    }

    // now reverse the sbox
    for(i=0; ARRAYSIZE(m_rgSbox) > i; ++i)
    {
        // if m_rgSbox[x] == y, m_rgReverseSbox[y] == x, so m_rgReverseSbox[m_rgSbox[x]] = x
        // example, if m_rgSbox[0] == 236, m_rgReverseSbox[236] = 0
        m_rgReverseSbox[m_rgSbox[i]] = static_cast<SPM_SBOX_WORD>(i);
    }

#ifdef _DEBUG
    // validate SBoxes
    UCHAR rgCount[SPM_SBOX_WIDTH];
    UCHAR rgReverseCount[SPM_SBOX_WIDTH];

    ::memset(rgCount, 0, sizeof(rgCount));
    ::memset(rgReverseCount, 0, sizeof(rgReverseCount));

    // initialize Sbox values to 0, 1, 2, ... N
    for (i = 0; SPM_SBOX_WIDTH > i; ++i)
    {
        ++(rgCount[m_rgSbox[i]]);
        ASSERT(rgCount[m_rgSbox[i]] <= 1)

        ++(rgReverseCount[m_rgReverseSbox[i]]);
        ASSERT(rgReverseCount[m_rgReverseSbox[i]] <= 1)
    }
#endif // _DEBUG

    if (s_eBlockMode == BLOCK_MODE::NoPermutation)
    {
        return;
    }
    
    // init m_rgBlockPermutation
    for (j = 0; 16 > j; ++j)
    {
        for (i = 0; ARRAYSIZE(m_rgBlockPermutation) > i; ++i)
        {
            // remember the current value for this entry
            nTemp = m_rgBlockPermutation[i];
            nRand = m_prngSBox.Rand() % ARRAYSIZE(m_rgBlockPermutation);

            // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
            m_rgBlockPermutation[i] = m_rgBlockPermutation[nRand];
            m_rgBlockPermutation[nRand] = static_cast<unsigned char>(nTemp);
        }
    }

#ifdef _DEBUG
    // validate SBoxes
    UCHAR rgBlockPermutationCount[ARRAYSIZE(m_rgBlockPermutation)];

    ::memset(rgBlockPermutationCount, 0, sizeof(rgBlockPermutationCount));

    // initialize Sbox values to 0, 1, 2, ... N
    for (i = 0; ARRAYSIZE(rgBlockPermutationCount) > i; ++i)
    {
        ++(rgBlockPermutationCount[m_rgBlockPermutation[i]]);
        ASSERT(rgBlockPermutationCount[m_rgBlockPermutation[i]] <= 1)
    }
#endif // _DEBUG
}

void CSpmBlockCipher64::ShuffleBlockPermutation(__out_ecount(k_cSpmBlockSizeBytes) unsigned char* rgBlockPermutation)
{
    size_t i;
    SPM_SBOX_WORD nTemp;
    SPM_SBOX_WORD nRand;

    ::memcpy(rgBlockPermutation, m_rgBlockPermutation, k_cSpmBlockSizeBytes);
    for (i = 0; k_cSpmBlockSizeBytes > i; ++i)
    {
        // remember the current value for this entry
        nTemp = rgBlockPermutation[i];
        nRand = m_prngSBox.Rand() % k_cSpmBlockSizeBytes;

        // swap the Sbox entry with another randomly chosen Sbox entry, which will preserve the permutation
        rgBlockPermutation[i] = rgBlockPermutation[nRand];
        rgBlockPermutation[nRand] = static_cast<unsigned char>(nTemp);
    }
}

void CSpmBlockCipher64::ReverseBlockPermutation(__in_ecount(k_cSpmBlockSizeBytes) const unsigned char* rgBlockPermutation, __out_ecount(k_cSpmBlockSizeBytes) unsigned char* rgReverseBlockPermutation)
{
    size_t i;
    for (i = 0; k_cSpmBlockSizeBytes > i; ++i)
    {
        // if m_rgBlockPermutation[x] == y, m_rgReverseBlockPermutation[y] == x, so m_rgReverseBlockPermutation[m_rgBlockPermutation[x]] = x
        // example, if m_rgBlockPermutation[0] == 236, m_rgReverseBlockPermutation[236] = 0
        ASSERT(rgBlockPermutation[i] < k_cSpmBlockSizeBytes);
        rgReverseBlockPermutation[rgBlockPermutation[i]] = static_cast<unsigned char>(i);
    }
}


bool CSpmBlockCipher64::s_ValidKey(__in_bcount(cbKeyData) const unsigned char * pKeyData, size_t cbKeyData)
{
    size_t cKeyWidth;
    cKeyWidth = s_GetKeyWidth();
    return (pKeyData != NULL) && (cbKeyData == cKeyWidth);
}

bool CSpmBlockCipher64::ValidKey(__in_bcount(cbKeyData) const unsigned char * pKeyData, size_t cbKeyData)
{
    return s_ValidKey(pKeyData, cbKeyData);
}

void CSpmBlockCipher64::SetKeys(__in_bcount(cbKeyData) const unsigned char * pKeyData, size_t cbKeyData)
{
    size_t cbPrngKeyWidth = SPM_PRNG::s_GetKeyWidth();
    ASSERT (cbKeyData >= cbPrngKeyWidth*2)
    m_prngSBox.SetKeys(pKeyData, cbPrngKeyWidth);
    m_prngMask.SetKeys(pKeyData + cbPrngKeyWidth, cbPrngKeyWidth);

    InitSbox();

    PermuteSbox();
}

void CSpmBlockCipher64::s_SmForwardPass(
    __inout_bcount(k_cSpmBlockSizeBytes) unsigned char* pBlock,
    __inout SPM_PRNG* pPrngMask,
    __in_ecount(SPM_SBOX_WIDTH) const SPM_SBOX_WORD* prgSbox)
{
    SPM_SBOX_WORD nMask;
    for (size_t k = 0; k < k_cSpmBlockInflectionIndex; ++k)
    {
        nMask = pPrngMask->Rand();
        *(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k)) ^= nMask;
        *(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k)) = prgSbox[*(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k))];
    }
}

void CSpmBlockCipher64::s_SmReversePass(
    __inout_bcount(k_cSpmBlockSizeBytes) unsigned char* pBlock,
    __inout SPM_PRNG* pPrngMask,
    __in_ecount(SPM_SBOX_WIDTH) const SPM_SBOX_WORD* prgSbox)
{
    // make sure size_t is unsigned so wrap-around terminates the loop
    C_ASSERT((((size_t)0) - 1) > 0);

    SPM_SBOX_WORD nMask;
    for (size_t k = k_cSpmBlockInflectionIndex - 2; k < k_cSpmBlockInflectionIndex; --k)
    {
        nMask = pPrngMask->Rand();
        *(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k)) ^= nMask;
        *(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k)) = prgSbox[*(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k))];
    }
}

void CSpmBlockCipher64::s_ApplyPermutation(
    __inout_bcount(k_cSpmBlockSizeBytes) unsigned char* pBlock,
    __in_ecount(k_cSpmBlockSizeBytes) const unsigned char* rgPermutation,
    __out_ecount(k_cSpmBlockSizeBytes) unsigned char* rgPermutationBuffer)
{
    for (size_t k = 0; k_cSpmBlockSizeBytes > k; ++k)
    {
        rgPermutationBuffer[rgPermutation[k]] = pBlock[k];
    }
    ::memcpy(pBlock, rgPermutationBuffer, k_cSpmBlockSizeBytes);
}

void CSpmBlockCipher64::s_EncryptRound(
    __inout_bcount(k_cSpmBlockSizeBytes) unsigned char* pBlock,
    __inout SPM_PRNG* pPrngMask,
    __in_ecount(SPM_SBOX_WIDTH) const SPM_SBOX_WORD* prgSbox,
    BLOCK_MODE eBlockMode,
    __in_ecount(k_cSpmBlockSizeBytes) const unsigned char* rgBlockPermutation,
    __out_ecount(k_cSpmBlockSizeBytes) unsigned char* rgPermutationBuffer)
{
    s_SmForwardPass(pBlock, pPrngMask, prgSbox);
    s_SmReversePass(pBlock, pPrngMask, prgSbox);

    if (eBlockMode == BLOCK_MODE::NoPermutation)
    {
        return;
    }

    s_ApplyPermutation(pBlock, rgBlockPermutation, rgPermutationBuffer);
}

void CSpmBlockCipher64::s_EncryptBlock(
    __inout_bcount(k_cSpmBlockSizeBytes) unsigned char* pBlock,
    __inout SPM_PRNG* pPrngMask,
    __inout SPM_PRNG* pPrngSBox,
    __in_ecount(SPM_SBOX_WIDTH) const SPM_SBOX_WORD* prgSbox,
    BLOCK_MODE eBlockMode,
    __in_ecount(k_cSpmBlockSizeBytes) const unsigned char* prgBaseBlockPermutation)
{
    unsigned char rgPermutationBuffer[k_cSpmBlockSizeBytes] = { 0 };
    unsigned char rgBlockPermutation[k_cSpmBlockSizeBytes] = { 0 };

    if (eBlockMode == BLOCK_MODE::Permutation)
    {
        // shuffle block permutation
        ::memcpy(rgBlockPermutation, prgBaseBlockPermutation, k_cSpmBlockSizeBytes);
        for (size_t i = 0; k_cSpmBlockSizeBytes > i; ++i)
        {
            SPM_SBOX_WORD nTemp = rgBlockPermutation[i];
            SPM_SBOX_WORD nRand = pPrngSBox->Rand() % k_cSpmBlockSizeBytes;
            rgBlockPermutation[i] = rgBlockPermutation[nRand];
            rgBlockPermutation[nRand] = static_cast<unsigned char>(nTemp);
        }
    }

    for (size_t j = 0; 3 > j; ++j)
    {
        s_EncryptRound(pBlock, pPrngMask, prgSbox, eBlockMode, rgBlockPermutation, rgPermutationBuffer);
    }
}

void CSpmBlockCipher64::Encrypt(__in_bcount(cbData) unsigned char * pData, size_t cbData)
{
    ASSERT ((cbData%k_cSpmBlockSizeBytes) == 0);

    for (size_t i = 0; i < cbData; i += k_cSpmBlockSizeBytes)
    {
        s_EncryptBlock(pData + i, &m_prngMask, &m_prngSBox, m_rgSbox, s_eBlockMode, m_rgBlockPermutation);
    }
}


void CSpmBlockCipher64::s_ReverseSmForwardPass(
    __inout_bcount(k_cSpmBlockSizeBytes) unsigned char* pBlock,
    __in_ecount(SPM_SBOX_WIDTH) const SPM_SBOX_WORD* prgReverseSbox,
    __in_ecount(6 * k_cSpmBlockInflectionIndex - 3) const SPM_SBOX_WORD* rgMask,
    __inout size_t* pl)
{
    for (size_t k = 0; k < k_cSpmBlockInflectionIndex; ++k)
    {
        ASSERT(*pl != 0);
        --(*pl);
        *(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k)) = prgReverseSbox[*(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k))];
        *(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k)) ^= rgMask[*pl];
    }
}

void CSpmBlockCipher64::s_ReverseSmReversePass(
    __inout_bcount(k_cSpmBlockSizeBytes) unsigned char* pBlock,
    __in_ecount(SPM_SBOX_WIDTH) const SPM_SBOX_WORD* prgReverseSbox,
    __in_ecount(6 * k_cSpmBlockInflectionIndex - 3) const SPM_SBOX_WORD* rgMask,
    __inout size_t* pl)
{
    // make sure size_t is unsigned so wrap-around terminates the loop
    C_ASSERT((((size_t)0) - 1) > 0);

    for (size_t k = k_cSpmBlockInflectionIndex - 2; k < k_cSpmBlockInflectionIndex; --k)
    {
        ASSERT(*pl != 0);
        --(*pl);
        *(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k)) = prgReverseSbox[*(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k))];
        *(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k)) ^= rgMask[*pl];
    }
}

void CSpmBlockCipher64::s_FillDecryptMasks(
    __out_ecount(6 * k_cSpmBlockInflectionIndex - 3) SPM_SBOX_WORD* rgMask,
    __inout SPM_PRNG* pPrngMask)
{
    size_t l = 0;
    for (size_t j = 0; 3 > j; ++j)
    {
        for (size_t k = 0; k < (2 * k_cSpmBlockInflectionIndex - 1); ++k)
        {
            rgMask[l] = pPrngMask->Rand();
            ++l;
        }
    }
}

void CSpmBlockCipher64::s_DecryptRound(
    __inout_bcount(k_cSpmBlockSizeBytes) unsigned char* pBlock,
    __in_ecount(SPM_SBOX_WIDTH) const SPM_SBOX_WORD* prgReverseSbox,
    __in_ecount(6 * k_cSpmBlockInflectionIndex - 3) const SPM_SBOX_WORD* rgMask,
    __inout size_t* pl,
    BLOCK_MODE eBlockMode,
    __in_ecount(k_cSpmBlockSizeBytes) const unsigned char* rgReverseBlockPermutation,
    __out_ecount(k_cSpmBlockSizeBytes) unsigned char* rgPermutationBuffer)
{
    if (eBlockMode == BLOCK_MODE::Permutation)
    {
        s_ApplyPermutation(pBlock, rgReverseBlockPermutation, rgPermutationBuffer);
    }

    s_ReverseSmForwardPass(pBlock, prgReverseSbox, rgMask, pl);
    s_ReverseSmReversePass(pBlock, prgReverseSbox, rgMask, pl);
}

void CSpmBlockCipher64::s_DecryptBlock(
    __inout_bcount(k_cSpmBlockSizeBytes) unsigned char* pBlock,
    __inout SPM_PRNG* pPrngMask,
    __inout SPM_PRNG* pPrngSBox,
    __in_ecount(SPM_SBOX_WIDTH) const SPM_SBOX_WORD* prgReverseSbox,
    BLOCK_MODE eBlockMode,
    __in_ecount(k_cSpmBlockSizeBytes) const unsigned char* prgBaseBlockPermutation)
{
    unsigned char rgPermutationBuffer[k_cSpmBlockSizeBytes] = { 0 };
    unsigned char rgBlockPermutation[k_cSpmBlockSizeBytes] = { 0 };
    unsigned char rgReverseBlockPermutation[k_cSpmBlockSizeBytes] = { 0 };
    SPM_SBOX_WORD rgMask[6 * k_cSpmBlockInflectionIndex - 3] = { 0 };

    if (eBlockMode == BLOCK_MODE::Permutation)
    {
        // shuffle block permutation
        ::memcpy(rgBlockPermutation, prgBaseBlockPermutation, k_cSpmBlockSizeBytes);
        for (size_t i = 0; k_cSpmBlockSizeBytes > i; ++i)
        {
            SPM_SBOX_WORD nTemp = rgBlockPermutation[i];
            SPM_SBOX_WORD nRand = pPrngSBox->Rand() % k_cSpmBlockSizeBytes;
            rgBlockPermutation[i] = rgBlockPermutation[nRand];
            rgBlockPermutation[nRand] = static_cast<unsigned char>(nTemp);
        }

        // build reverse permutation
        for (size_t i = 0; k_cSpmBlockSizeBytes > i; ++i)
        {
            ASSERT(rgBlockPermutation[i] < k_cSpmBlockSizeBytes);
            rgReverseBlockPermutation[rgBlockPermutation[i]] = static_cast<unsigned char>(i);
        }
    }

    s_FillDecryptMasks(rgMask, pPrngMask);

    size_t l = 6 * k_cSpmBlockInflectionIndex - 3;

    // j is unsigned, so 3 > j is equivalent to j >= 0 because 0-1 == 0xffffffffffffffff
    for (size_t j = 2; 3 > j; --j)
    {
        s_DecryptRound(pBlock, prgReverseSbox, rgMask, &l, eBlockMode, rgReverseBlockPermutation, rgPermutationBuffer);
    }
}

void CSpmBlockCipher64::Decrypt(__in_bcount(cbData) unsigned char * pData, size_t cbData)
{
    ASSERT ((cbData%k_cSpmBlockSizeBytes) == 0);

    // make sure size_t is unsigned
    C_ASSERT ((((size_t)0)-1) > 0);

    for (size_t i = 0; i < cbData; i += k_cSpmBlockSizeBytes)
    {
        s_DecryptBlock(pData + i, &m_prngMask, &m_prngSBox, m_rgReverseSbox, s_eBlockMode, m_rgBlockPermutation);
    }
}


