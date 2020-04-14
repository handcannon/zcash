#include "poc.h"
#include "../chain.h"
#include <vector>

using namespace std;

#ifdef __cplusplus
extern "C" {
#endif
#include <crypto/sph_shabal.h>
#ifdef __cplusplus
}
#endif

#define HASH_SIZE 32
#define HASH_CAP 4096
#define SCOOP_SIZE 64
#define PLOT_SIZE (HASH_CAP * SCOOP_SIZE) // 4096*64

const uint64_t INITIAL_BASE_TARGET = 18325193796L;
const uint64_t MAX_BASE_TARGET = 18325193796L;


uint256 CalcGenerationSignature(uint256 lastSig, uint160 lastPlotID)
{
    vector<unsigned char> signature(lastSig.size() + lastPlotID.size());
    memcpy(&signature[0], lastSig.begin(), lastSig.size());
    memcpy(&signature[lastSig.size()], lastPlotID.begin(), lastPlotID.size());
    /*
    unsigned char* vx = (unsigned char*)&lastPlotID;
    for (auto i = 0; i < sizeof(lastPlotID); i++) {
        signature[lastSig.size() + i] = *(vx + 7 - i);
    }
    */
	sph_shabal256_context ctx;
    sph_shabal256_init(&ctx);
    sph_shabal256(&ctx, &signature[0], signature.size());
    vector<unsigned char> res(32);
    sph_shabal256_close(&ctx, &res[0]);
    return uint256(res);
}

/*
vector<uint8_t> genNonceChunk(const uint64_t plotID, const uint64_t nonce)
{
    sph_shabal256_context ctx;
    vector<uint8_t> genData(16 + PLOT_SIZE);
    //put plotID
    uint8_t* xv = (uint8_t*)&plotID;
    for (size_t i = 0; i < 8; i++) {
        genData[PLOT_SIZE + i] = xv[7 - i];
    }
    //put nonce
    xv = (uint8_t*)&nonce;
    for (size_t i = 8; i < 16; i++) {
        genData[PLOT_SIZE + i] = xv[15 - i];
    }
    for (auto i = PLOT_SIZE; i > 0; i -= HASH_SIZE) {
        sph_shabal256_init(&ctx);
        auto len = PLOT_SIZE + 16 - i;
        if (len > HASH_CAP) len = HASH_CAP;
        sph_shabal256(&ctx, &genData[i], len);
        sph_shabal256_close(&ctx, &genData[i - HASH_SIZE]);
    }
    sph_shabal256_init(&ctx);
    sph_shabal256(&ctx, &genData[0], 16 + PLOT_SIZE);
    vector<uint8_t> final(32);
    sph_shabal256_close(&ctx, &final[0]);
    // XOR with final
    for (size_t i = 0; i < PLOT_SIZE; i++) {
        genData[i] ^= (final[i % HASH_SIZE]);
    }
    
    vector<uint8_t> data(PLOT_SIZE);
    for (size_t i = 0; i < PLOT_SIZE; i += HASH_SIZE) {
        if ((i / HASH_SIZE) % 2 == 0) {
            memmove(&data[i], &genData[i], HASH_SIZE);
        } else {
            memmove(&data[i], &genData[PLOT_SIZE - i], HASH_SIZE);
        }
    }
    return std::move(data);
}
*/
vector<uint8_t> genNonceChunk(const uint160 plotID, const uint64_t nonce)
{
    sph_shabal256_context ctx;
    vector<uint8_t> genData(28 + PLOT_SIZE);

    //put plotID
    //uint8_t* xv = (uint8_t*)&plotID;
    //for (size_t i = 0; i < 8; i++) {
    //    genData[PLOT_SIZE + i] = xv[7 - i];
    //}
    //memcpy(&genData[PLOT_SIZE], plotID.begin(), plotID.size());
    uint8_t* xv = (uint8_t*)&plotID;
    for (size_t i = 0; i < 20; i++) {
        genData[PLOT_SIZE + i] = xv[19 - i];
    }

    //put nonce
    xv = (uint8_t*)&nonce;
    for (size_t i = 20; i < 28; i++) {
        genData[PLOT_SIZE + i] = xv[27 - i];
    }

    for (auto i = PLOT_SIZE; i > 0; i -= HASH_SIZE) {
        sph_shabal256_init(&ctx);
        auto len = PLOT_SIZE + 28 - i;
        if (len > HASH_CAP)
            len = HASH_CAP;
        sph_shabal256(&ctx, &genData[i], len);
        sph_shabal256_close(&ctx, &genData[i - HASH_SIZE]);
    }
    sph_shabal256_init(&ctx);
    sph_shabal256(&ctx, &genData[0], 28 + PLOT_SIZE);
    vector<uint8_t> final(32);
    sph_shabal256_close(&ctx, &final[0]);
    // XOR with final
    for (size_t i = 0; i < PLOT_SIZE; i++) {
        genData[i] ^= (final[i % HASH_SIZE]);
    }

    vector<uint8_t> data(PLOT_SIZE);
    for (size_t i = 0; i < PLOT_SIZE; i += HASH_SIZE) {
        if ((i / HASH_SIZE) % 2 == 0) {
            memmove(&data[i], &genData[i], HASH_SIZE);
        } else {
            memmove(&data[i], &genData[PLOT_SIZE - i], HASH_SIZE);
        }
    }
    return std::move(data);
}

uint64_t CalcDeadline(const uint256 genSig, const uint64_t height, const uint160 plotID, const uint64_t nonce)
{
    vector<uint8_t> scoopGen(40);
    memcpy(&scoopGen[0], genSig.begin(), genSig.size());
    const uint8_t* mov = (uint8_t*)&height;
    scoopGen[32] = mov[7];
    scoopGen[33] = mov[6];
    scoopGen[34] = mov[5];
    scoopGen[35] = mov[4];
    scoopGen[36] = mov[3];
    scoopGen[37] = mov[2];
    scoopGen[38] = mov[1];
    scoopGen[39] = mov[0];
    sph_shabal256_context ctx;
    sph_shabal256_init(&ctx);
    sph_shabal256(&ctx, &scoopGen[0], 40);
    char genHash[32];
    sph_shabal256_close(&ctx, genHash);
    uint32_t scoop = (((unsigned char)genHash[31]) + 256 * (unsigned char)genHash[30]) % 4096;

    auto chunk = genNonceChunk(plotID, nonce);
    vector<uint8_t> sig(32 + 64);
    memcpy(&sig[0], genSig.begin(), genSig.size());
    memcpy(&sig[32], &chunk[scoop * 64], sizeof(uint8_t) * 64);
    sph_shabal256_init(&ctx);
    sph_shabal256(&ctx, &sig[0], 64 + 32);
    vector<uint8_t> res(32);
    sph_shabal256_close(&ctx, &res[0]);
    uint64_t* wertung = (uint64_t*)&res[0];
    return *wertung;
}

uint64_t CalcDeadline(const CBlockHeader* block, const CBlockIndex* prevBlock)
{
    auto generationSig = CalcGenerationSignature(prevBlock->genSign, prevBlock->nPlotID);
    return CalcDeadline(generationSig, prevBlock->nHeight+1, block->nPlotID, block->nNonce);
}

bool CheckProofOfCapacity(const uint256 genSig, const uint64_t height, const uint160 plotID, const uint64_t nonce, const uint64_t baseTarget, const uint64_t deadline, const uint64_t targetDeadline)
{
    auto dl = CalcDeadline(genSig, height, plotID, nonce);
    return (dl == deadline) && (targetDeadline >= dl / baseTarget);
}

uint64_t AdjustBaseTarget(const CBlockIndex* prevBlock, const uint32_t nTime)
{
    return INITIAL_BASE_TARGET * 100;

    if (prevBlock == nullptr) 
        return INITIAL_BASE_TARGET;
    auto height = prevBlock->nHeight + 1;
    if (height < 4) {
        return INITIAL_BASE_TARGET;
    }
    if (height < 2700) {
        auto itBlock = prevBlock;
        uint64_t avgBaseTarget = itBlock->nBaseTarget;

        do {
            itBlock = itBlock->pprev;
            avgBaseTarget += itBlock->nBaseTarget;
        } while (itBlock->nHeight > height - 4);

        avgBaseTarget = avgBaseTarget / 4;

        uint64_t difTime = nTime - itBlock->nTime;

        uint64_t curBaseTarget = avgBaseTarget;
        uint64_t newBaseTarget = curBaseTarget * difTime / (240 * 4);

        if (newBaseTarget < 0 || newBaseTarget > MAX_BASE_TARGET) {
            newBaseTarget = MAX_BASE_TARGET;
        }

        if (newBaseTarget == 0) {
            newBaseTarget = 1;
        }

        // Adjust range should at [0.9, 1.1]
        if (newBaseTarget < (curBaseTarget * 9 / 10)) {
            newBaseTarget = curBaseTarget * 9 / 10;
        } else if (newBaseTarget > (curBaseTarget * 11 / 10)) {
            newBaseTarget = curBaseTarget * 11 / 10;
        }

        return newBaseTarget; 
    }
    auto itBlock = prevBlock;
    uint64_t expBaseTarget = itBlock->nBaseTarget;
    int blockCounter = 1;

    // Calculate EV of last 30 blocks
    do {
        itBlock = itBlock->pprev;
        blockCounter++;
        expBaseTarget = (expBaseTarget * blockCounter + itBlock->nBaseTarget) / (blockCounter + 1);
    } while (blockCounter < 24);

    uint64_t difTime = nTime - itBlock->nTime;
    uint64_t targetTimespan = 24 * 4 * 60;

    if (difTime < targetTimespan / 2) {
        difTime = targetTimespan / 2;
    } else if (difTime > targetTimespan * 2) {
        difTime = targetTimespan * 2;
    }

    uint64_t curBaseTarget = prevBlock->nBaseTarget;
    uint64_t newBaseTarget = expBaseTarget * difTime / targetTimespan;

    if (newBaseTarget < 0 || newBaseTarget > MAX_BASE_TARGET) {
        newBaseTarget = MAX_BASE_TARGET;
    }

    if (newBaseTarget == 0) {
        newBaseTarget = 1;
    }

    if (newBaseTarget < (curBaseTarget * 8 / 10)) {
        newBaseTarget = curBaseTarget * 8 / 10;
    } else if (newBaseTarget > (curBaseTarget * 12 / 10)) {
        newBaseTarget = curBaseTarget * 12 / 10;
    }

    return newBaseTarget;

}

void AdjustBaseTarget(const CBlockIndex* prevBlock, CBlock* block)
{
    if (block)
        block->nBaseTarget = INITIAL_BASE_TARGET * 100;
    return;

    // 1. Gensis block
    auto height = 0;
    if (prevBlock != nullptr) {
        height = prevBlock->nHeight + 1;
    }
    if (prevBlock == nullptr || height == 0) {
        block->nBaseTarget = INITIAL_BASE_TARGET;
        // 2. First 4 blocks
    } else if (height < 4) {
        block->nBaseTarget = INITIAL_BASE_TARGET;
        // 3. First 2700 blocks
    } else if (height < 2700) {
        auto itBlock = prevBlock;
        uint64_t avgBaseTarget = itBlock->nBaseTarget;

        do {
            itBlock = itBlock->pprev;
            avgBaseTarget += itBlock->nBaseTarget;
        } while (itBlock->nHeight > height - 4);

        avgBaseTarget = avgBaseTarget / 4;

        uint64_t difTime = block->nTime - itBlock->nTime;

        uint64_t curBaseTarget = avgBaseTarget;
        uint64_t newBaseTarget = curBaseTarget * difTime / (240 * 4);

        if (newBaseTarget < 0 || newBaseTarget > MAX_BASE_TARGET) {
            newBaseTarget = MAX_BASE_TARGET;
        }

        if (newBaseTarget == 0) {
            newBaseTarget = 1;
        }

        // Adjust range should at [0.9, 1.1]
        if (newBaseTarget < (curBaseTarget * 9 / 10)) {
            newBaseTarget = curBaseTarget * 9 / 10;
        } else if (newBaseTarget > (curBaseTarget * 11 / 10)) {
            newBaseTarget = curBaseTarget * 11 / 10;
        }

        block->nBaseTarget = newBaseTarget;
    } else { // 4. Later blocks
        auto itBlock = prevBlock;
        uint64_t expBaseTarget = itBlock->nBaseTarget;
        int blockCounter = 1;

        // Calculate EV of last 30 blocks
        do {
            itBlock = itBlock->pprev;
            blockCounter++;
            expBaseTarget = (expBaseTarget * blockCounter + itBlock->nBaseTarget) / (blockCounter + 1);
        } while (blockCounter < 24);

        uint64_t difTime = block->nTime - itBlock->nTime;
        uint64_t targetTimespan = 24 * 4 * 60;

        if (difTime < targetTimespan / 2) {
            difTime = targetTimespan / 2;
        }

        if (difTime > targetTimespan * 2) {
            difTime = targetTimespan * 2;
        }

        uint64_t curBaseTarget = prevBlock->nBaseTarget;
        uint64_t newBaseTarget = expBaseTarget * difTime / targetTimespan;

        if (newBaseTarget < 0 || newBaseTarget > MAX_BASE_TARGET) {
            newBaseTarget = MAX_BASE_TARGET;
        }

        if (newBaseTarget == 0) {
            newBaseTarget = 1;
        }

        if (newBaseTarget < (curBaseTarget * 8 / 10)) {
            newBaseTarget = curBaseTarget * 8 / 10;
        } else if (newBaseTarget > (curBaseTarget * 12 / 10)) {
            newBaseTarget = curBaseTarget * 12 / 10;
        }

        block->nBaseTarget = newBaseTarget;
    }
}
