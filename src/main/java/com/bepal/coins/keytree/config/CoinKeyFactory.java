package com.bepal.coins.keytree.config;

import com.bepal.coins.keytree.coinkey.*;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoin;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.model.HDKey;

public class CoinKeyFactory {

    // 使用java模版优化或使用反射
    static public ICoinKey get(CoinTag coinTag, HDKey hdKey) {
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

            case tagBYTOM:
            case tagBYTOMTEST:
            case tagBYTOMSOLO:
                return new BytomKey(hdKey,netType);

            case tagELASTOS:
            case tagELASTOSTEST:
                return new ElastosKey(hdKey,netType);

            case tagEOS:
            case tagEOSTEST:
                return new EosKey(hdKey,netType);

            case tagETHEREUM:
            case tagETHEREUMTEST:
                return new EthereumKey(hdKey,netType);

            case tagGXCHAIN:
            case tagGXCHAINTEST:
                return new GXChainKey(hdKey,netType);

        }
        return null;

    }
}
