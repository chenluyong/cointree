package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.keytree.infrastructure.interfaces.ICoin;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.model.HDKey;

public class CoinKeyFactory {
    static public ICoinKey getConfig(CoinTag coinTag, HDKey hdKey) {
        // net type
        ICoinKey.NetType netType = ICoin.NetType.MAIN;
        if (coinTag.compareTo(CoinTag.tagTESTBEGIN) > 0
                && coinTag.compareTo(CoinTag.tagTESTEND) < 0) {
            netType = ICoin.NetType.TEST;
        }
        else if (coinTag.compareTo(CoinTag.tagTESTEND) > 0) {
            netType = ICoin.NetType.SOLO;
        }

        switch (coinTag) {
            case tagBITCOINTEST:
            case tagBITCOIN:
                return new BitcoinKey(hdKey,netType);

            case tagAChain:
            case tagACHAINTEST:
                return new AChainKey(hdKey,netType);

        }
        return null;
    }
}
