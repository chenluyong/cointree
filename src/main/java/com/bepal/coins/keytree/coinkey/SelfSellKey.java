package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoinKey;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;

public class SelfSellKey extends AChainKey {

    public SelfSellKey(ECKey ecKey) {
        super(new HDKey(ecKey), CoinConfigFactory.getConfig(CoinTag.tagSELFSELL));
    }
    public SelfSellKey(HDKey hdKey) {
        super(hdKey,CoinConfigFactory.getConfig(CoinTag.tagSELFSELL));
    }
    public SelfSellKey(HDKey hdKey, NetType netType) {
        super(hdKey,CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagSELFSELL : CoinTag.tagSELFSELLTEST)
        );
    }


    @Override
    protected String getHeader() {
        return "SSC";
    }
}
