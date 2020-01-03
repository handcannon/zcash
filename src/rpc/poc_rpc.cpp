// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "poc_rpc.h"
#include "poc.h"
#include "chainparams.h"
#include "key_io.h"
#include "keystore.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"
#include "coincontrol.h"
#include "wallet/wallet.h"

#include <algorithm>
#include <queue>
#include <wallet/rpcwallet.h>
//#include <ticket.h>
//#include <consensus/tx_verify.h>
#include <net.h>
//#include <validation.h>
#include "main.h"
#include "init.h"
#include "rpc/util_rpc.h"
//#include "server.h"

UniValue getAddressPlotId(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{
                "getaddressplotid",
                "\nReturns a plot id.",
                {{"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Your miner address"}},
                RPCResult{
                    "{\n"
                    "  \"plotid\": nnn, (numeric) The plot id\n"
                    "}\n"},
                RPCExamples{
                    HelpExampleCli("getaddressplotid", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"") + HelpExampleRpc("getaddressplotid", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"")},
            }
                .ToString());
    }

    /*
    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    auto wallet = wallets.size() == 1 || (fHelp && wallets.size() > 0) ? wallets[0] : nullptr;
    if (wallet == nullptr) {
        return NullUniValue;
    }
    CWallet* const pwallet = wallet.get();
    
    if (!pwalletMain)
        return NullUniValue;
    auto locked_chain = pwalletMain->chain().lock();
    LOCK(pwallet->cs_wallet);
    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
    LOCK(cs_main);
    std::string strAddress = params[0].get_str();
    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }
    auto keyid = GetKeyForDestination(*pwallet, dest);
    if (keyid.IsNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    */

    if (!pwalletMain)
        return NullUniValue;

    
    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    
    LOCK(pwalletMain->cs_wallet);

    std::string strAddress = params[0].get_str();
    CTxDestination dest = DecodeDestination(strAddress);

    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");

    CKey key;
    CKeyID keyid  = boost::get<CKeyID>(dest);
    if (!pwalletMain->GetKey(keyid, key))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("plotid", keyid.GetPlotID());
    return obj;
}

UniValue getMiningInfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{
                "getmininginfo",
                "\nReturns info for poc mining.",
                {},
                RPCResult{
                    "{\n"
                    "  \"height\": nnn\n"
                    "  \"generationSignature\": \"xxx\"\n"
                    "  \"cumulativeDiff\": \"xxx\"\n"
                    "  \"basetarget\": nnn\n"
                    "  \"targetDeadline\": nnn\n"
                    "}\n"},
                RPCExamples{
                    HelpExampleCli("getmininginfo", "") + HelpExampleRpc("getmininginfo", "")},
            }
                .ToString());
    }
    LOCK(cs_main);

    auto height = chainActive.Height() + 1;
    auto diff = chainActive.Tip()->nCumulativeDiff;
    auto block = chainActive.Tip()->GetBlockHeader();
    auto generationSignature = CalcGenerationSignature(block.genSign, block.nPlotID);
    auto nBaseTarget = block.nBaseTarget;
    auto param = Params();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("height", height);
    obj.pushKV("generationSignature", HexStr<uint256>(generationSignature));
    obj.pushKV("cumulativeDiff", diff.GetHex());
    obj.pushKV("baseTarget", nBaseTarget);
    obj.pushKV("targetDeadline", param.TargetDeadline());
    return obj;
}

UniValue submitNonce(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 4) {
        throw std::runtime_error(
            RPCHelpMan{
                "submitnonce",
                "\nSubmit the nonce form disk.",
                {{"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Your miner address"},
                    {"nonce", RPCArg::Type::STR, RPCArg::Optional::NO, "The nonce you found on disk"},
                    {"deadline", RPCArg::Type::NUM, RPCArg::Optional::NO, "When the next block will be generate"},
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block height you want to mine"},},
                RPCResult{
                    "{\n"
                    "  \"accetped\": ture or false\n"
                    "  \"deadline\": \"nnn\"\n"
                    "}\n"},
                RPCExamples{
                    HelpExampleCli("submitnonce", "\"3MhzFQAXQMsmtTmdkciLE3EJsgAQkzR4Sg\" 15032170525642997731 6170762982435 100") + HelpExampleRpc("submitnonce", "\"3MhzFQAXQMsmtTmdkciLE3EJsgAQkzR4Sg\", 15032170525642997731, 6170762982435 100")},
            }
                .ToString());
    }

    /*
    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    auto wallet = wallets.size() == 1 || (fHelp && wallets.size() > 0) ? wallets[0] : nullptr;
    if (wallet == nullptr) {
        return NullUniValue;
    }
    CWallet* const pwallet = wallet.get();
    auto locked_chain = pwallet->chain().lock();

    std::string strAddress = params[0].get_str();
    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest) && dest.type() != typeid(CKeyID)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }
    auto keyid = boost::get<CKeyID>(dest);
    auto plotID = boost::get<CKeyID>(dest).GetPlotID();
    uint64_t nonce = 0;
    auto nonceStr = params[1].get_str();
    if (!ParseUInt64(nonceStr, &nonce)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid nonce");
    }
    uint64_t deadline = params[2].get_int64();
    int height = params[3].get_int();
    CKey key;
    LOCK(pwallet->cs_wallet);
    if (!pwallet->IsLocked()) {
        pwallet->GetKey(keyid, key);
    }
    */
    
    if (!pwalletMain)
        return NullUniValue;
    
    std::string strAddress = params[0].get_str();
    auto nonceStr          = params[1].get_str();
    uint64_t deadline      = params[2].get_int64();
    int height             = params[3].get_int();

    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest) && dest.type() != typeid(CKeyID))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    auto keyid  = boost::get<CKeyID>(dest);
    auto plotID = boost::get<CKeyID>(dest).GetPlotID();

    CKey key;
    LOCK(pwalletMain->cs_wallet);
    if (!pwalletMain->IsLocked()) {
        pwalletMain->GetKey(keyid, key);
    }

    uint64_t nonce = 0;
    if (!ParseUInt64(nonceStr, &nonce))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid nonce");
    
    UniValue obj(UniValue::VOBJ);
    if (blockAssembler.UpdateDeadline(height, keyid, nonce, deadline, key)) {
        obj.pushKV("plotid", plotID);
        obj.pushKV("deadline", deadline);
        auto params = Params();
        obj.pushKV("targetdeadline", params.TargetDeadline());
    } else {
        obj.pushKV("accept", false);
    }

    return obj;
}

uint256 SendAction(CWallet *const pwallet, const CAction& action, const CKey &key, CTxDestination destChange)
{
    auto locked_chain = pwallet->chain().lock();
    CAmount curBalance = pwallet->GetBalance();
    auto actionFee = Params().GetConsensus().nActionFee;

    std::vector<CRecipient> vecSend;
    vecSend.push_back(CRecipient{ GetScriptForDestination(destChange), actionFee, false });
    auto newTx = MakeTransactionRef();
    CReserveKey reservekey(pwallet);
    int nChangePosInOut = 0;
    CAmount nFeeRequired;
    std::string strError;
    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = true;
    coinControl.destChange = destChange;
    if (!pwallet->CreateTransaction(*locked_chain, vecSend, newTx, reservekey, nFeeRequired, nChangePosInOut, strError, coinControl, false)) {
        if (nFeeRequired > curBalance)
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    
    CMutableTransaction mtx(*newTx);
    BOOST_ASSERT(mtx.vout.size() == 2);
    std::vector<unsigned char> vch;
    auto out = mtx.vin[0].prevout;
    if (!SignAction(out, action, key, vch)) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Private key sign error");
    }
    auto opRetScript = CScript() << OP_RETURN << ToByteVector(vch);
    mtx.vout[1] = CTxOut(0, opRetScript);
    mtx.vout[nChangePosInOut].nValue += nFeeRequired;

    if (!pwallet->SignTransaction(mtx)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "sign error");
    }
    const CAmount highfee{ actionFee };
    uint256 txid;
    std::string err_string;
    auto tx = MakeTransactionRef(CTransaction(mtx));
    CValidationState state;
    if (!pwallet->CommitTransaction(tx, mapValue_t{}, {}, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    return std::move(tx->GetHash());
}

static UniValue bindplotid(const UniValue& params, bool fHelp)
{
    /*
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }*/

    if (!pwalletMain)
        return NullUniValue;

    if (fHelp || params.size() != 2) {
        throw std::runtime_error(
            RPCHelpMan{
            "bindplotid",
            "\nbind plotid to another address.",
            {
                { "from", RPCArg::Type::STR, RPCArg::Optional::NO, "address" },
                { "to", RPCArg::Type::STR, RPCArg::Optional::NO, "target" },
            },
            RPCResult{
                    "\"txid\"                  (string) The transaction id.\n"
                },
                RPCExamples{
                        HelpExampleCli("bindplotid", "17VkcJoDJEHyuCKgGyky8CGNnb1kPgbwr4 1QEWDafENaWingtsSGtnc3M2fiQVuEkZHi")
                    },
        }.ToString()
        );
    }
    LOCK(pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    auto checkAddress = [](std::string str) ->bool {
        CTxDestination dest = DecodeDestination(str);
        return IsValidDestination(dest) && dest.type() == typeid(CKeyID);
    };
    if (!checkAddress(params[0].get_str()) || !checkAddress(params[1].get_str())) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }
    std::string strAddress = params[0].get_str();
    CTxDestination dest = DecodeDestination(strAddress);
    //auto from = GetKeyForDestination(*pwalletMain, dest);
    auto from  = boost::get<CKeyID>(dest);

    if (from.IsNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    auto to = boost::get<CKeyID>(DecodeDestination(params[1].get_str()));
    auto action = MakeBindAction(from, to);
    CKey key;
    if (!pwalletMain->GetKey(from, key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }

    return NullUniValue;

    //auto txid = SendAction(pwallet, action, key, CTxDestination(from));
    //return txid.GetHex();
}

/*
static UniValue unbindplotid(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{
            "unbindplotid",
            "\nunbind plotid mapping.",
            {
                { "from", RPCArg::Type::STR, RPCArg::Optional::NO, "address" },
            },
            RPCResult{
                    "\"txid\"                  (string) The transaction id.\n"
                },
                RPCExamples{
                        HelpExampleCli("unbindplotid", "17VkcJoDJEHyuCKgGyky8CGNnb1kPgbwr4")
                    },
        }.ToString()
        );
    }
    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);
    auto strAddress = request.params[0].get_str();
    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest) || dest.type() != typeid(CKeyID)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }
    auto from = GetKeyForDestination(*pwallet, dest);
    if (from.IsNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    auto action = CAction(CUnbindAction(from));
    CKey key;
    if (!pwallet->GetKey(from, key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }
    auto txid = SendAction(pwallet, action, key, CTxDestination(from));
    return txid.GetHex();
}
*/

static UniValue getbindinginfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{
            "getbindinginfo",
            "\nunbind plotid mapping.",
            {
                { "address", RPCArg::Type::STR, RPCArg::Optional::NO, "address" },
            },
            RPCResult{
                    "{\n"
                    "  \"from\": {\n"
                    "    \"address\": \"17VkcJoDJEHyuCKgGyky8CGNnb1kPgbwr4\",\n"
                    "    \"plotid\": 8512475111423,\n"
                    "  },\n"
                    "  \"to\": {\n"
                    "    \"address\": \"1QEWDafENaWingtsSGtnc3M2fiQVuEkZHi\",\n"
                    "    \"plotid\": 14776299456771222,\n"
                    "  }\n"
                    "}\n"
                },
                RPCExamples{
                        HelpExampleCli("getbindinginfo", "17VkcJoDJEHyuCKgGyky8CGNnb1kPgbwr4")
                    },
        }.ToString()
        );
    }
    LOCK(cs_main);
    auto strAddress = params[0].get_str();
    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest) || dest.type() != typeid(CKeyID)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }
    auto from = boost::get<CKeyID>(dest);
    //auto to = prelationview->To(from);
    CKeyID to;
    if (to == CKeyID()) {
        return UniValue(UniValue::VOBJ);
    }
    UniValue fromVal(UniValue::VOBJ);
    fromVal.pushKV("address", EncodeDestination(CTxDestination(from)));
    fromVal.pushKV("plotid", from.GetPlotID());

    UniValue toVal(UniValue::VOBJ);
    toVal.pushKV("address", EncodeDestination(CTxDestination(to)));
    toVal.pushKV("plotid", to.GetPlotID());
    UniValue result(UniValue::VOBJ);
    result.pushKV("from", fromVal);
    result.pushKV("to", toVal);
    return result;
}

static UniValue listbindings(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{
            "listbindings",
            "\nlist all binding infos.",
            {},
            RPCResult{
                "[\n"
                "  {\n"
                "    \"from\": {\n"
                "      \"address\": \"1LfaqrJ9vrXTU3RdVTsHz7Dgn5b1ooN8KN\",\n"
                "      \"plotid\": 14045118739489404631,\n"
                "    },\n"
                "    \"to\": {\n"
                "      \"address\": \"1GwFgPsGwmyohfMCbdD6tGCYMNzbeK1N4V\",\n"
                "      \"plotid\": 12495994880773508270,\n"
                "    }\n"
                "  },\n"
                "  {\n"
                "    \"from\": {\n"
                "      \"address\": \"1JWYKVAY2r73FbMxwZdgwXaHPwT2srRrUx\",\n"
                "      \"plotid\": 8195665653426294976,\n"
                "    },\n"
                "    \"to\": {\n"
                "      \"address\": \"1MxchR6KHhE44M4KGPMRJtftY5jcXZ3nfA\",\n"
                "      \"plotid\": 13765273405587843045,\n"
                "    }\n"
                "  }\n"
                "]\n"
            },
            RPCExamples{
                    HelpExampleCli("listbindings", "")
                },
        }.ToString()
        );
    }
    LOCK(cs_main);
    UniValue results(UniValue::VARR);
    for (auto relation : prelationview->ListRelations()) {
        auto from = relation.first;
        auto to = relation.second;
        UniValue fromVal(UniValue::VOBJ);
        fromVal.pushKV("address", EncodeDestination(CTxDestination(from)));
        fromVal.pushKV("plotid", from.GetPlotID());

        UniValue toVal(UniValue::VOBJ);
        toVal.pushKV("address", EncodeDestination(CTxDestination(to)));
        toVal.pushKV("plotid", to.GetPlotID());

        UniValue val(UniValue::VOBJ);
        val.pushKV("from", fromVal);
        val.pushKV("to", toVal);
        results.push_back(val);
    }
    return results;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "poc",               "getmininginfo",           &getMiningInfo,          true },
    { "poc",               "submitnonce",             &submitNonce,            true },
	{ "poc",               "getaddressplotid",        &getAddressPlotId,       true },
    //{ "poc",               "bindplotid",              &bindplotid,             true },
    //{ "poc",               "unbindplotid",            &unbindplotid,           true },
    //{ "poc",               "listbindings",            &listbindings,           true },
    //{ "poc",               "getbindinginfo",          &getbindinginfo,         true },
};

void RegisterPocRPCCommands(CRPCTable& t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
