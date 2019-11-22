#ifndef LAVA_Assembler_H
#define LAVA_Assembler_H

#include <config/bitcoin-config.h>
#include <pubkey.h>
#include <key.h>
#include <chain.h>

class CPOCBlockAssembler
{
public:
    CPOCBlockAssembler();

    ~CPOCBlockAssembler() = default;

    bool UpdateDeadline(const int height, const CKeyID& keyid, const uint64_t nonce, const uint64_t deadline, const CKey& key);

    void CreateNewBlock();

    void SetNull();

    //void SetFirestoneAt(const CKey& sourceKey);

    void CheckDeadline();

private:
    uint256       genSig;
    int           height;
    CKeyID        keyid;
    uint64_t      nonce;
    uint64_t      deadline;
    uint64_t      dl;
    CKey          key;
    CKey          firestoneKey;
    boost::mutex  mtx;
};

#endif // BITCOIN_Assembler_H
