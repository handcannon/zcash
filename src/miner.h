// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include "primitives/block.h"

#include <boost/optional.hpp>
#include <stdint.h>

class CBlockIndex;
class CChainParams;
class CScript;
namespace Consensus { struct Params; };

struct CBlockTemplate
{
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
};

/** Generate a new block, without valid proof-of-work */
CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& scriptPubKeyIn, uint64_t nonce = 0, uint160 plotID = uint160(), uint64_t deadline = 0);

#ifdef ENABLE_MINING
/** Get script for -mineraddress */
void GetScriptForMinerAddress(boost::shared_ptr<CReserveScript> &script);
/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, uint64_t nExtraNonce);
/** Run the miner threads */
void GenerateBitcoins(bool fGenerate, int nThreads, const CChainParams& chainparams);
#endif

void UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

#endif // BITCOIN_MINER_H
