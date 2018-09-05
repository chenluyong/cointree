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


        switch (coinTag) {
            case tagBITCOINTEST:
            case tagBITCOIN:
                return new CoinConfig(DeriveTag.tagBITCOIN, coinTag, SeedTag.tagBITCOIN,
                        SignerTag.tagSECP256K1, 0, netType,pubPrefix,prvPrefix);

            case tagAChain:
            case tagACHAINTEST:
                return new CoinConfig(DeriveTag.tagBITCOIN, coinTag, SeedTag.tagBITCOIN,
                        SignerTag.tagSECP256K1, 666, netType,pubPrefix,prvPrefix);

            case tagBYTOM:
            case tagBYTOMTEST:
            case tagBYTOMSOLO:
                return new CoinConfig(DeriveTag.tagED25519, coinTag, SeedTag.tagHMAC512_ROOT,
                        SignerTag.tagED25519, 153, netType,pubPrefix,prvPrefix);

        }


        return null;
    }

}
