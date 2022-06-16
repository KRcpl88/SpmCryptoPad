#pragma once

typedef unsigned __int64 SPM_WORD;
typedef unsigned short SPM_SBOX_WORD;

const size_t k_cSpmBlockSizeWords = 16;
const size_t k_cSpmBlockSizeBytes = k_cSpmBlockSizeWords * sizeof (SPM_WORD);
const size_t k_cSpmBlockInflectionIndex = k_cSpmBlockSizeBytes - sizeof (SPM_SBOX_WORD) + 1; // reverse point for encrypting block
const size_t k_cSpmBlockSizeBits = k_cSpmBlockSizeBytes * 8;

const size_t k_cSpmWordWidthBits = 8 * sizeof (SPM_WORD);
const size_t k_cSpmSBoxWidthBits = 8 * sizeof (SPM_SBOX_WORD);

// defines log base 2 of the width of a FBC_WORD in bytes, for 64 bit words log2(8) = 3
#define SPM_LOG2_WORD_WIDTH 3


// must be 2^k_cSpmSBoxWidthBits;
#define SPM_SBOX_WIDTH	0x10000


unsigned long NormalizeKey(unsigned long ulRawKey);
bool IsCoprime(unsigned long* pMatch, size_t cchMatch, unsigned long ulTest);
bool IsMatch(unsigned long* pMatch, size_t cchMatch, unsigned long ulTest);

class CSimplePrng64 
{
    SPM_WORD m_wState;
    SPM_WORD m_wKey;
    size_t m_idx;

public:
    CSimplePrng64();
    void SetKeys(__in_ecount(cKeyData) const unsigned char *  pKeyData, size_t cKeyData);
    inline SPM_SBOX_WORD Rand()
    {
        if (m_idx >= (sizeof(SPM_WORD) / sizeof(SPM_SBOX_WORD)))
        {
            m_idx=0;
            m_wState += m_wKey;
        }

        return reinterpret_cast<SPM_SBOX_WORD*>(&m_wState)[m_idx++];
    }

    static size_t s_GetKeyWidth()
    {
      size_t cKeyWidth;
      cKeyWidth = 2 * sizeof(SPM_WORD);
      return cKeyWidth;
    }
};




typedef CSimplePrng64 SPM_PRNG;
// Each CSimplePRNG key is 2 64 bit words (m_wState and m_wKey), and we need 3 of them
#define SPM_PRNG_NUM_KEYS   2


class CSpmBlockCipher64
{
public: 
    enum BLOCK_MODE {Permutation, NoPermutation};
    CSpmBlockCipher64()
    {
        ::memset(m_rgSbox, 0, sizeof(m_rgSbox));
        ::memset(m_rgBlockPermutation, 0, sizeof(m_rgBlockPermutation));
    }

protected:
    SPM_PRNG m_prngSBox;
    SPM_PRNG m_prngMask;
    SPM_SBOX_WORD m_rgSbox[SPM_SBOX_WIDTH];
    SPM_SBOX_WORD m_rgReverseSbox[SPM_SBOX_WIDTH];
    unsigned char m_rgBlockPermutation[k_cSpmBlockSizeBytes];
    static BLOCK_MODE s_eBlockMode;

protected:
    void InitSbox();

    void PermuteSbox();

    void ShuffleBlockPermutation(__out_ecount(k_cSpmBlockSizeBytes) unsigned char* rgBlockPermutation);
    void ReverseBlockPermutation(__in_ecount(k_cSpmBlockSizeBytes) const unsigned char* rgBlockPermutation, __out_ecount(k_cSpmBlockSizeBytes) unsigned char* rgReverseBlockPermutation);

public:
    static SPM_SBOX_WORD s_rgCodebook[SPM_SBOX_WIDTH];
    static unsigned char* s_prgPermutationCodebook;

    static void s_ConstructCodebook(BLOCK_MODE eBlockMode);
    static void s_PermuteCodebook(int n, __in_ecount(cKeyData) const unsigned char* pKeyData, size_t cKeyData);
    static void s_CheckCodebook();

    static size_t s_GetKeyWidth()
    {
        size_t cKeyWidth;
        cKeyWidth = SPM_PRNG::s_GetKeyWidth() *2;
        return cKeyWidth;
    }

    static bool s_ValidKey(__in_bcount(cKeyData) const unsigned char * pKeyData, size_t cbKeyData);

    virtual bool ValidKey(__in_bcount(cKeyData) const unsigned char * pKeyData, size_t cbKeyData);

    virtual void SetKeys(__in_bcount(cKeyData) const unsigned char * pKeyData, size_t cbKeyData);

    // encryption and decryption are symetric opertations
    virtual void Encrypt(__in_bcount(cbData) unsigned char * pData, size_t cbData);
    virtual void Decrypt(__in_bcount(cbData) unsigned char * pData, size_t cbData);
};

typedef CSpmBlockCipher64 FBC_CRYPT;
