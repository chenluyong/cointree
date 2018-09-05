package com.bepal.coins.keytree.config;

import com.bepal.coins.keytree.infrastructure.interfaces.ICoin;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;

public class CoinConfigFactory {
    // https://gitlab.eshanren.com/chenluyong/bepal/blob/master/doc/protocol/table.md
    static public CoinConfig getConfig(CoinTag coinTag) {
        // net type
        ICoinKey.NetType netType = ICoin.NetType.MAIN;
        if (coinTag.compareTo(CoinTag.tagTESTBEGIN) > 0
                && coinTag.compareTo(CoinTag.tagTESTEND) < 0) {
            netType = ICoin.NetType.TEST;
        }
        else if (coinTag.compareTo(CoinTag.tagTESTEND) > 0) {
            netType = ICoin.NetType.SOLO;
        }
        // bip32 header
        int pubPrefix = 0x0488B21E; // xpub
        int prvPrefix = 0x0488ADE4; // xprv
        if (netType != ICoin.NetType.MAIN) {
            pubPrefix = 0x043587CF; // tpub
            prvPrefix = 0x04358394; // tprv
        }
        // bip44
        int bip44 = getBip44(coinTag);
        if (-1 == bip44) {
            return null;
        }

        switch (coinTag) {
            case tagGXCHAIN:
            case tagGXCHAINTEST:
            case tagAChain:
            case tagACHAINTEST:
            case tagETHEREUM:
            case tagETHEREUMTEST:
            case tagBITCOINTEST:
            case tagBITCOIN:
                return new CoinConfig(DeriveTag.tagDEFAULT, coinTag, SeedTag.tagDEFAULT,
                        SignerTag.tagSECP256K1, bip44, netType,pubPrefix,prvPrefix);

            case tagBYTOM:
            case tagBYTOMTEST:
            case tagBYTOMSOLO:
                return new CoinConfig(DeriveTag.tagED25519, coinTag, SeedTag.tagHMAC512_ROOT,
                        SignerTag.tagED25519, 153, netType,pubPrefix,prvPrefix);

            case tagELASTOS:
            case tagELASTOSTEST:
                return new CoinConfig(DeriveTag.tagSECP256R1, coinTag, SeedTag.tagDEFAULT,
                        SignerTag.tagSECP256R1, 2305, netType, pubPrefix, prvPrefix);

            case tagEOS:
            case tagEOSTEST:
                return new CoinConfig(DeriveTag.tagDEFAULT, coinTag, SeedTag.tagDEFAULT,
                        SignerTag.tagSECP256K1NONCE, 194, netType,pubPrefix, prvPrefix);


        }


        return null;
    }


    static public int getBip44(CoinTag coinTag) {
        int ret = -1;
        switch (coinTag) {
            case tagBITCOIN:
            case tagBITCOINTEST:
                return 0;
            case tagETHEREUM:
            case tagETHEREUMTEST:
                return 60;
            case tagBYTOM:
            case tagBYTOMSOLO:
            case tagBYTOMTEST:
                return 153;
            case tagEOS:
            case tagEOSTEST:
                return 194;
            case tagGXCHAIN:
            case tagGXCHAINTEST:
                return 2303;
            case tagSELFSELL:
            case tagSELFSELLTEST:
                return 2304;
            case tagAChain:
            case tagACHAINTEST:
                return 666;
            case tagELASTOS:
            case tagELASTOSTEST:
                return 2305;

        }
        return ret;
    }

}
