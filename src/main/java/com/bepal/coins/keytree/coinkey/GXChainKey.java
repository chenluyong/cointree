package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoinKey;
import com.bepal.coins.keytree.infrastructure.components.GrapheneSerializer;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;

public class GXChainKey extends ACoinKey {

    public GXChainKey(ECKey ecKey) {
        super(new HDKey(ecKey), CoinConfigFactory.getConfig(CoinTag.tagGXCHAIN));
    }
    public GXChainKey(HDKey hdKey) {
        super(hdKey,CoinConfigFactory.getConfig(CoinTag.tagGXCHAIN));
    }
    public GXChainKey(HDKey hdKey, NetType netType) {
        super(hdKey,CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagGXCHAIN : CoinTag.tagGXCHAINTEST)
        );
    }


    @Override
    public String address() {
        return publicKey();
    }
    @Override
    public String publicKey() {
        return "GXC"+ GrapheneSerializer.serializePubKey(this.base().getPubKey());
    }

    @Override
    public String privateKey() {
        return GrapheneSerializer.wifPriKey(this.base().getPriKey());
    }

}
