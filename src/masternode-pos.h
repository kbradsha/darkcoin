

// Copyright (c) 2009-2012 The Darkcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef MASTERNODE_POS_H
#define MASTERNODE_POS_H

#include "bignum.h"
#include "sync.h"
#include "net.h"
#include "key.h"
#include "core.h"
#include "util.h"
#include "script.h"
#include "base58.h"
#include "main.h"

using namespace std;
using namespace boost;

class CMasternodePOSCheck;

extern map<uint256, CMasternodePOSCheck> mapMasternodePosCheck;
extern CMasternodeScanning mnscan;

static const int MIN_MASTERNODE_POS_PROTO_VERSION = 70066;

/*
	1% of the network is scanned every 2.5 minutes, making a full
	round of scanning take about 4.16 hours. We're targeting about 
	a day of proof-of-service errors for complete removal from the 
	masternode system.
*/
static const int MASTERNODE_SCANNING_ERROR_THESHOLD = 6;

#define SCANNING_SUCCESS                       1
#define SCANNING_ERROR_NO_RESPONSE             2
#define SCANNING_ERROR_IX_NO_RESPONSE          3
#define SCANNING_ERROR_MAX                     3

void inline ProcessMessageMasternodePOS(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

class CMasternodeScanning
{
public:
    void DoMasternodePOSChecks();
    void CleanMasternodeScanningErrors();
}

// Returns how many masternodes are allowed to scan each block
int GetCountScanningPerBlock()
{
	return max(1, mnodeman.CountMasternodesAboveProtocol(MIN_MASTERNODE_POS_PROTO_VERSION)*0.01);
}

class CMasternodeScanningError
{
public:
    CTxIn vinMasternodeA;
    CTxIn vinMasternodeB;
    int nErrorType;
    int nExpiration;
    int nBlockHeight;
    std::vector<unsigned char> vchMasterNodeSignature;

    CMasternodeScanningError::CMasternodeScanningError (CTxIn vinMasternodeAIn, CTxIn vinMasternodeBIn, int nErrorTypeIn, int nBlockHeightIn)
    {
    	vinMasternodeA = vinMasternodeAIn;
    	vinMasternodeB = vinMasternodeBIn;
    	nErrorType = nErrorTypeIn;
    	nExpiration = GetTime()+(60*60);
    	nBlockHeight = nBlockHeightIn;
    }

    uint256 GetHash() const {return SerializeHash(*this);}

    bool SignatureValid();
    bool Sign();
    bool IsExpired() {return GetTime() > nExpiration;}
    void Relay();
    void IsValid() {
    	return nErrorType > 0 && nErrorType <= SCANNING_ERROR_MAX;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vinMasternodeA);
        READWRITE(vinMasternodeB);
        READWRITE(nErrorType);
        READWRITE(nExpiration);
        READWRITE(nBlockHeight);
        READWRITE(vchMasterNodeSignature);
    )
};
