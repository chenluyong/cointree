package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoinKey;
import com.bepal.coins.keytree.infrastructure.components.GrapheneSerializer;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;

public class EosKey extends ACoinKey {

    public EosKey(ECKey ecKey) {
        super(new HDKey(ecKey),CoinConfigFactory.getConfig(CoinTag.tagEOS));
    }
    public EosKey(HDKey hdKey) {
        super(hdKey,CoinConfigFactory.getConfig(CoinTag.tagEOS));
    }
    public EosKey(HDKey hdKey, NetType netType) {
        super(hdKey,CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagEOS : CoinTag.tagEOSTEST)
        );
    }


    @Override
    public String address() {
        return publicKey();
    }

    public String publicKey() {
        return  "EOS"+ GrapheneSerializer.serializePubKey(this.base().getPubKey());
    }

    @Override
    public String privateKey() {
        return GrapheneSerializer.wifPriKey(this.base().getPriKey());
    }
}
