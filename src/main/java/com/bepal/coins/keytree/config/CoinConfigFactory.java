package com.bepal.coins.keytree.config;

import com.bepal.coins.keytree.infrastructure.interfaces.ICoin;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;


public class CoinConfigFactory {

    static public CoinConfig getConfig(CoinTag coinTag) {
        // bip44
        int bip44 = getBip44(coinTag);
        if (-1 == bip44) {
            return null;
        }

        switch (coinTag) {
            case tagGXCHAIN:
            case tagGXCHAINTEST:
            case tagSELFSELL:
            case tagSELFSELLTEST:
            case tagAChain:
            case tagACHAINTEST:
            case tagETHEREUM:
            case tagETHEREUMTEST:
            case tagBITCOINTEST:
            case tagBITCOIN:
                return new CoinConfig(DeriveTag.tagDEFAULT, coinTag, SeedTag.tagDEFAULT,
                        SignerTag.tagSECP256K1, bip44, coinTag.getNetType(),
                        coinTag.getPubPrefix(),coinTag.getPrvPrefix());

            case tagBYTOM:
            case tagBYTOMTEST:
            case tagBYTOMSOLO:
                return new CoinConfig(DeriveTag.tagED25519, coinTag, SeedTag.tagHMAC512_ROOT,
                        SignerTag.tagED25519, 153, coinTag.getNetType(),
                        coinTag.getPubPrefix(),coinTag.getPrvPrefix());

            case tagELASTOS:
            case tagELASTOSTEST:
                return new CoinConfig(DeriveTag.tagSECP256R1, coinTag, SeedTag.tagDEFAULT,
                        SignerTag.tagSECP256R1, 2305, coinTag.getNetType(),
                        coinTag.getPubPrefix(),coinTag.getPrvPrefix());

            case tagEOS:
            case tagEOSTEST:
                return new CoinConfig(DeriveTag.tagDEFAULT, coinTag, SeedTag.tagDEFAULT,
                        SignerTag.tagSECP256K1NONCE, 194, coinTag.getNetType(),
                        coinTag.getPubPrefix(),coinTag.getPrvPrefix());
            default:
                break;
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
